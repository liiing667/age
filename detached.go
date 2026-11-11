package age

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"slices"

	"filippo.io/age/internal/format"
	"filippo.io/age/internal/stream"
)

// ErrUnboundHeader is returned when a detached header is used without a
// verifiable binding to a ciphertext.
var ErrUnboundHeader = errors.New("age: detached header is not bound to a ciphertext")

// ErrHeaderBindingMismatch is returned when a detached header binding does
// not match the header or ciphertext metadata it is used with.
var ErrHeaderBindingMismatch = errors.New("age: detached header binding mismatch")

// ErrMultipleHeaders is returned when a detached header input contains more
// than one age header.
var ErrMultipleHeaders = format.ErrMultipleHeaders

// ErrTrailingHeaderData is returned when a detached header input contains
// trailing data after the header.
var ErrTrailingHeaderData = format.ErrTrailingHeaderData

const headerBindingMagic = "age-detached-header-binding/v1\x00"

var ageIntro = []byte("age-encryption.org/v1\n")

// HeaderBinding binds the canonical fingerprint of a detached header to the
// nonce and encrypted payload length of the ciphertext it belongs to.
//
// A binding is created by [ExtractHeaderBinding] and can be stored alongside
// the detached header. [DecryptHeaderBinding] refuses to return a file key
// unless the supplied binding matches the header. This catches a header from
// one file being used with another file before the payload is read.
//
// ArtifactID is an optional caller-provided identifier. When set, it is
// included in the binding and can additionally be checked at decryption time.
type HeaderBinding struct {
	// Fingerprint is the SHA-256 digest of the canonical detached header,
	// including its MAC.
	Fingerprint [sha256.Size]byte

	// Nonce is the nonce at the start of the encrypted payload.
	Nonce [streamNonceSize]byte

	// PayloadSize is the length in bytes of the encrypted payload after the
	// nonce.
	PayloadSize int64

	// ArtifactID is an optional caller-provided identifier for the artifact
	// the header belongs to.
	ArtifactID []byte
}

// DetachedHeaderBinding is an alias for [HeaderBinding].
type DetachedHeaderBinding = HeaderBinding

// NewHeaderBinding creates a binding for header from already known ciphertext
// metadata. The optional artifactID may be a string or a []byte.
func NewHeaderBinding(header, nonce []byte, payloadSize int64, artifactID ...any) (*HeaderBinding, error) {
	fingerprint, err := HeaderFingerprint(header)
	if err != nil {
		return nil, err
	}
	id, err := parseArtifactID(artifactID)
	if err != nil {
		return nil, err
	}
	if len(nonce) != streamNonceSize {
		return nil, fmt.Errorf("%w: invalid nonce length %d", ErrHeaderBindingMismatch, len(nonce))
	}
	if _, err := stream.EncryptedChunkCount(payloadSize); err != nil {
		return nil, fmt.Errorf("%w: invalid encrypted payload length %d: %v", ErrHeaderBindingMismatch, payloadSize, err)
	}
	var n [streamNonceSize]byte
	copy(n[:], nonce)
	return &HeaderBinding{
		Fingerprint: fingerprint,
		Nonce:       n,
		PayloadSize: payloadSize,
		ArtifactID:  slices.Clone(id),
	}, nil
}

// HeaderFingerprint returns the canonical fingerprint of a single detached
// header. It rejects trailing data and concatenated headers.
func HeaderFingerprint(header []byte) ([sha256.Size]byte, error) {
	hdr, err := format.ParseExact(header)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return hdr.Fingerprint()
}

// CanonicalHeader returns the canonical serialization of a single detached
// header. It rejects trailing data and concatenated headers.
func CanonicalHeader(header []byte) ([]byte, error) {
	hdr, err := format.ParseExact(header)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := hdr.Marshal(&buf); err != nil {
		return nil, fmt.Errorf("failed to serialize header: %w", err)
	}
	return buf.Bytes(), nil
}

// ExtractHeaderBinding extracts a detached header and a binding to the nonce
// and encrypted payload length that follow it in src.
//
// Unlike [ExtractHeader], this function reads src through the payload to
// determine its length and to reject truncated payloads. It also rejects
// sources that contain a second age header immediately after the first one.
// The optional artifactID may be a string or a []byte.
//
// The returned binding should be stored alongside the detached header. Use
// [DecryptHeaderBinding] to verify it before returning a file key.
//
// This is a low-level function that most users won't need.
func ExtractHeaderBinding(src io.Reader, artifactID ...any) (header []byte, binding *HeaderBinding, err error) {
	id, err := parseArtifactID(artifactID)
	if err != nil {
		return nil, nil, err
	}
	header, binding, _, err = extractHeaderBinding(src, id)
	return header, binding, err
}

// ExtractHeaderBindingAt is like [ExtractHeaderBinding], but it reads at most
// encryptedSize bytes from src and rejects ciphertexts shorter than
// encryptedSize.
//
// This is a low-level function that most users won't need.
func ExtractHeaderBindingAt(src io.ReaderAt, encryptedSize int64, artifactID ...any) (header []byte, binding *HeaderBinding, err error) {
	if encryptedSize < 0 {
		return nil, nil, fmt.Errorf("invalid encrypted size: %d", encryptedSize)
	}
	id, err := parseArtifactID(artifactID)
	if err != nil {
		return nil, nil, err
	}
	section := io.NewSectionReader(src, 0, encryptedSize)
	header, binding, total, err := extractHeaderBinding(section, id)
	if err != nil {
		return nil, nil, err
	}
	if total != encryptedSize {
		return nil, nil, fmt.Errorf("%w: truncated ciphertext: expected %d bytes, read %d", ErrHeaderBindingMismatch, encryptedSize, total)
	}
	return header, binding, nil
}

func extractHeaderBinding(src io.Reader, artifactID []byte) (header []byte, binding *HeaderBinding, total int64, err error) {
	cr := &countingReader{r: src}
	hdr, payload, err := format.Parse(cr)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to read header: %w", err)
	}

	var headerBuf bytes.Buffer
	if err := hdr.Marshal(&headerBuf); err != nil {
		return nil, nil, 0, fmt.Errorf("failed to serialize header: %w", err)
	}

	// Read enough of the payload to cover both the nonce and the intro of a
	// possible second header. A real payload starts with a random 16-byte
	// nonce, so it can't be confused with an age intro except with negligible
	// probability.
	prefix := make([]byte, len(ageIntro))
	n, readErr := io.ReadFull(payload, prefix)
	if readErr != nil && !errors.Is(readErr, io.EOF) && !errors.Is(readErr, io.ErrUnexpectedEOF) {
		return nil, nil, 0, fmt.Errorf("failed to read payload: %w", readErr)
	}
	if n == len(prefix) && bytes.Equal(prefix, ageIntro) {
		return nil, nil, 0, ErrMultipleHeaders
	}
	if n < streamNonceSize {
		return nil, nil, 0, fmt.Errorf("failed to read nonce: %w", io.ErrUnexpectedEOF)
	}

	var nonce [streamNonceSize]byte
	copy(nonce[:], prefix[:streamNonceSize])

	rest, err := io.Copy(io.Discard, payload)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to read payload: %w", err)
	}
	payloadSize := int64(n-streamNonceSize) + rest
	if _, err := stream.EncryptedChunkCount(payloadSize); err != nil {
		return nil, nil, 0, fmt.Errorf("invalid encrypted payload length %d: %w", payloadSize, err)
	}

	fingerprint, err := hdr.Fingerprint()
	if err != nil {
		return nil, nil, 0, fmt.Errorf("failed to compute header fingerprint: %w", err)
	}

	binding = &HeaderBinding{
		Fingerprint: fingerprint,
		Nonce:       nonce,
		PayloadSize: payloadSize,
		ArtifactID:  slices.Clone(artifactID),
	}
	return headerBuf.Bytes(), binding, cr.n, nil
}

// DecryptHeaderBinding decrypts a detached header after verifying that its
// binding matches the header. The returned file key can be used with
// [NewInjectedFileKeyIdentity].
//
// The binding may be a HeaderBinding, *HeaderBinding, or the binary form
// produced by [HeaderBinding.MarshalBinary]. The optional arguments after the
// binding may be identities and, if an artifact ID was used when the binding
// was created, the expected artifact ID as a string or []byte. An [io.Reader]
// may also be supplied, in which case the binding is checked against the
// header, nonce, and payload length of the ciphertext read from it. The reader
// is consumed.
//
// A missing or malformed binding is rejected with [ErrUnboundHeader], a
// mismatch with [ErrHeaderBindingMismatch], and concatenated headers with
// [ErrMultipleHeaders].
//
// This is a low-level function that most users won't need.
func DecryptHeaderBinding(header []byte, binding any, args ...any) ([]byte, error) {
	hdr, expected, err := parseBoundHeader(header)
	if err != nil {
		return nil, err
	}
	b, err := normalizeHeaderBinding(binding)
	if err != nil {
		return nil, err
	}
	if err := b.verify(expected); err != nil {
		return nil, err
	}

	identities, artifactID, source, err := parseDecryptArgs(args)
	if err != nil {
		return nil, err
	}
	if artifactID != nil && !bytes.Equal(b.ArtifactID, artifactID) {
		return nil, fmt.Errorf("%w: artifact ID does not match", ErrHeaderBindingMismatch)
	}
	if source != nil {
		if err := verifyHeaderBindingSource(expected, b, source); err != nil {
			return nil, err
		}
	}
	return decryptHdr(hdr, identities...)
}

// DecryptHeaderBindingCiphertext is like [DecryptHeaderBinding], but it also
// verifies the binding against the actual nonce and encrypted payload length
// of the ciphertext being decrypted.
//
// This is a low-level function that most users won't need.
func DecryptHeaderBindingCiphertext(header []byte, binding any, nonce []byte, payloadSize int64, args ...any) ([]byte, error) {
	hdr, expected, err := parseBoundHeader(header)
	if err != nil {
		return nil, err
	}
	b, err := normalizeHeaderBinding(binding)
	if err != nil {
		return nil, err
	}
	if err := b.verify(expected); err != nil {
		return nil, err
	}
	if err := b.verifyCiphertext(nonce, payloadSize); err != nil {
		return nil, err
	}

	identities, artifactID, _, err := parseDecryptArgs(args)
	if err != nil {
		return nil, err
	}
	if artifactID != nil && !bytes.Equal(b.ArtifactID, artifactID) {
		return nil, fmt.Errorf("%w: artifact ID does not match", ErrHeaderBindingMismatch)
	}
	return decryptHdr(hdr, identities...)
}

// DecryptHeaderBindingForCiphertext is like [DecryptHeaderBinding], but it
// verifies the binding against the ciphertext read from src before returning
// a file key. The reader is consumed.
func DecryptHeaderBindingForCiphertext(header []byte, binding any, src io.Reader, args ...any) ([]byte, error) {
	args = append([]any{src}, args...)
	return DecryptHeaderBinding(header, binding, args...)
}

// ExtractHeaderBound is an alias for [ExtractHeaderBinding].
func ExtractHeaderBound(src io.Reader, artifactID ...any) ([]byte, *HeaderBinding, error) {
	return ExtractHeaderBinding(src, artifactID...)
}

// ExtractHeaderAndBinding is an alias for [ExtractHeaderBinding].
func ExtractHeaderAndBinding(src io.Reader, artifactID ...any) ([]byte, *HeaderBinding, error) {
	return ExtractHeaderBinding(src, artifactID...)
}

// ExtractHeaderWithBinding is an alias for [ExtractHeaderBinding].
func ExtractHeaderWithBinding(src io.Reader, artifactID ...any) ([]byte, *HeaderBinding, error) {
	return ExtractHeaderBinding(src, artifactID...)
}

// ExtractDetachedHeaderBinding is an alias for [ExtractHeaderBinding].
func ExtractDetachedHeaderBinding(src io.Reader, artifactID ...any) ([]byte, *HeaderBinding, error) {
	return ExtractHeaderBinding(src, artifactID...)
}

// DecryptHeaderBound is an alias for [DecryptHeaderBinding].
func DecryptHeaderBound(header []byte, binding any, args ...any) ([]byte, error) {
	return DecryptHeaderBinding(header, binding, args...)
}

// DecryptHeaderAndBinding is an alias for [DecryptHeaderBinding].
func DecryptHeaderAndBinding(header []byte, binding any, args ...any) ([]byte, error) {
	return DecryptHeaderBinding(header, binding, args...)
}

// DecryptHeaderWithBinding is an alias for [DecryptHeaderBinding].
func DecryptHeaderWithBinding(header []byte, binding any, args ...any) ([]byte, error) {
	return DecryptHeaderBinding(header, binding, args...)
}

// DecryptDetachedHeaderBinding is an alias for [DecryptHeaderBinding].
func DecryptDetachedHeaderBinding(header []byte, binding any, args ...any) ([]byte, error) {
	return DecryptHeaderBinding(header, binding, args...)
}

// VerifyHeaderBinding checks that binding matches the canonical fingerprint
// of a single detached header. If an expected artifact ID is supplied as a
// string or []byte, it is checked as well.
func VerifyHeaderBinding(header []byte, binding any, artifactID ...any) error {
	expected, err := HeaderFingerprint(header)
	if err != nil {
		return err
	}
	b, err := normalizeHeaderBinding(binding)
	if err != nil {
		return err
	}
	if err := b.verify(expected); err != nil {
		return err
	}
	id, err := parseArtifactID(artifactID)
	if err != nil {
		return err
	}
	if id != nil && !bytes.Equal(b.ArtifactID, id) {
		return fmt.Errorf("%w: artifact ID does not match", ErrHeaderBindingMismatch)
	}
	return nil
}

// VerifyHeaderBindingCiphertext verifies a binding against a detached header,
// the ciphertext nonce, and the encrypted payload length.
func VerifyHeaderBindingCiphertext(header []byte, binding any, nonce []byte, payloadSize int64, artifactID ...any) error {
	if err := VerifyHeaderBinding(header, binding, artifactID...); err != nil {
		return err
	}
	b, err := normalizeHeaderBinding(binding)
	if err != nil {
		return err
	}
	return b.verifyCiphertext(nonce, payloadSize)
}

// VerifyHeaderBindingForCiphertext verifies a binding against a detached
// header and the ciphertext read from src. The reader is consumed.
func VerifyHeaderBindingForCiphertext(header []byte, binding any, src io.Reader, artifactID ...any) error {
	if err := VerifyHeaderBinding(header, binding, artifactID...); err != nil {
		return err
	}
	expected, err := HeaderFingerprint(header)
	if err != nil {
		return err
	}
	b, err := normalizeHeaderBinding(binding)
	if err != nil {
		return err
	}
	return verifyHeaderBindingSource(expected, b, src)
}

// Verify checks that b matches the canonical fingerprint of header.
func (b *HeaderBinding) Verify(header []byte) error {
	return VerifyHeaderBinding(header, b)
}

// VerifyCiphertext checks that b matches header, nonce, and payloadSize.
func (b *HeaderBinding) VerifyCiphertext(header, nonce []byte, payloadSize int64) error {
	return VerifyHeaderBindingCiphertext(header, b, nonce, payloadSize)
}

func (b *HeaderBinding) verify(expected [sha256.Size]byte) error {
	if err := b.validate(); err != nil {
		return err
	}
	if b.Fingerprint != expected {
		return fmt.Errorf("%w: header fingerprint does not match", ErrHeaderBindingMismatch)
	}
	return nil
}

func (b *HeaderBinding) verifyCiphertext(nonce []byte, payloadSize int64) error {
	if len(nonce) != streamNonceSize {
		return fmt.Errorf("%w: invalid nonce length %d", ErrHeaderBindingMismatch, len(nonce))
	}
	if !bytes.Equal(b.Nonce[:], nonce) {
		return fmt.Errorf("%w: ciphertext nonce does not match", ErrHeaderBindingMismatch)
	}
	if _, err := stream.EncryptedChunkCount(payloadSize); err != nil {
		return fmt.Errorf("%w: invalid encrypted payload length %d: %v", ErrHeaderBindingMismatch, payloadSize, err)
	}
	if b.PayloadSize != payloadSize {
		return fmt.Errorf("%w: ciphertext payload length does not match", ErrHeaderBindingMismatch)
	}
	return nil
}

func verifyHeaderBindingSource(expected [sha256.Size]byte, b *HeaderBinding, src io.Reader) error {
	_, actual, _, err := extractHeaderBinding(src, nil)
	if err != nil {
		return err
	}
	if actual.Fingerprint != expected {
		return fmt.Errorf("%w: ciphertext header does not match", ErrHeaderBindingMismatch)
	}
	return b.verifyCiphertext(actual.Nonce[:], actual.PayloadSize)
}

func (b *HeaderBinding) validate() error {
	if b == nil || b.Fingerprint == ([sha256.Size]byte{}) {
		return ErrUnboundHeader
	}
	if _, err := stream.EncryptedChunkCount(b.PayloadSize); err != nil {
		return fmt.Errorf("%w: invalid encrypted payload length %d: %v", ErrHeaderBindingMismatch, b.PayloadSize, err)
	}
	return nil
}

// MarshalBinary returns a canonical binary encoding of b, suitable for
// storing alongside a detached header.
func (b *HeaderBinding) MarshalBinary() ([]byte, error) {
	if err := b.validate(); err != nil {
		return nil, err
	}
	if uint64(len(b.ArtifactID)) > uint64(^uint32(0)) {
		return nil, errors.New("age: artifact ID is too large")
	}

	buf := bytes.NewBuffer(make([]byte, 0, len(headerBindingMagic)+sha256.Size+streamNonceSize+8+4+len(b.ArtifactID)))
	buf.WriteString(headerBindingMagic)
	buf.Write(b.Fingerprint[:])
	buf.Write(b.Nonce[:])
	var payloadSize [8]byte
	binary.BigEndian.PutUint64(payloadSize[:], uint64(b.PayloadSize))
	buf.Write(payloadSize[:])
	var artifactLen [4]byte
	binary.BigEndian.PutUint32(artifactLen[:], uint32(len(b.ArtifactID)))
	buf.Write(artifactLen[:])
	buf.Write(b.ArtifactID)
	return buf.Bytes(), nil
}

// ParseHeaderBinding parses the binary encoding produced by
// [HeaderBinding.MarshalBinary].
func ParseHeaderBinding(data []byte) (*HeaderBinding, error) {
	b, err := parseHeaderBinding(data)
	if err != nil {
		return nil, err
	}
	if err := b.validate(); err != nil {
		return nil, err
	}
	return b, nil
}

// UnmarshalBinary parses the binary encoding produced by
// [HeaderBinding.MarshalBinary] into b.
func (b *HeaderBinding) UnmarshalBinary(data []byte) error {
	parsed, err := ParseHeaderBinding(data)
	if err != nil {
		return err
	}
	*b = *parsed
	return nil
}

func parseHeaderBinding(data []byte) (*HeaderBinding, error) {
	if len(data) == 0 {
		return nil, ErrUnboundHeader
	}
	if !bytes.HasPrefix(data, []byte(headerBindingMagic)) {
		return nil, fmt.Errorf("%w: malformed binding", ErrUnboundHeader)
	}
	data = data[len(headerBindingMagic):]
	const fixedSize = sha256.Size + streamNonceSize + 8 + 4
	if len(data) < fixedSize {
		return nil, fmt.Errorf("%w: truncated binding", ErrUnboundHeader)
	}

	b := &HeaderBinding{}
	copy(b.Fingerprint[:], data[:sha256.Size])
	data = data[sha256.Size:]
	copy(b.Nonce[:], data[:streamNonceSize])
	data = data[streamNonceSize:]
	b.PayloadSize = int64(binary.BigEndian.Uint64(data[:8]))
	if b.PayloadSize < 0 {
		return nil, fmt.Errorf("%w: invalid payload length", ErrUnboundHeader)
	}
	data = data[8:]
	artifactLen := binary.BigEndian.Uint32(data[:4])
	data = data[4:]
	if uint64(len(data)) != uint64(artifactLen) {
		return nil, fmt.Errorf("%w: truncated artifact ID", ErrUnboundHeader)
	}
	b.ArtifactID = slices.Clone(data)
	return b, nil
}

func parseBoundHeader(header []byte) (*format.Header, [sha256.Size]byte, error) {
	hdr, err := format.ParseExact(header)
	if err != nil {
		return nil, [sha256.Size]byte{}, err
	}
	fingerprint, err := hdr.Fingerprint()
	if err != nil {
		return nil, [sha256.Size]byte{}, fmt.Errorf("failed to compute header fingerprint: %w", err)
	}
	return hdr, fingerprint, nil
}

func normalizeHeaderBinding(binding any) (*HeaderBinding, error) {
	switch b := binding.(type) {
	case nil:
		return nil, ErrUnboundHeader
	case *HeaderBinding:
		if b == nil {
			return nil, ErrUnboundHeader
		}
		return b, nil
	case HeaderBinding:
		return &b, nil
	case []byte:
		return parseHeaderBinding(b)
	case string:
		return parseHeaderBinding([]byte(b))
	default:
		return nil, fmt.Errorf("age: unsupported header binding type %T", binding)
	}
}

func parseDecryptArgs(args []any) (identities []Identity, artifactID []byte, source io.Reader, err error) {
	var artifactSet bool
	for _, arg := range args {
		switch v := arg.(type) {
		case nil:
			continue
		case Identity:
			identities = append(identities, v)
		case io.Reader:
			if source != nil {
				return nil, nil, nil, errors.New("age: multiple ciphertext readers")
			}
			source = v
		case string:
			if artifactSet {
				return nil, nil, nil, errors.New("age: multiple artifact IDs")
			}
			artifactID, artifactSet = []byte(v), true
		case []byte:
			if artifactSet {
				return nil, nil, nil, errors.New("age: multiple artifact IDs")
			}
			artifactID, artifactSet = v, true
		default:
			return nil, nil, nil, fmt.Errorf("age: unsupported argument type %T", arg)
		}
	}
	return identities, artifactID, source, nil
}

func parseArtifactID(args []any) ([]byte, error) {
	var id []byte
	for _, arg := range args {
		switch v := arg.(type) {
		case nil:
			continue
		case string:
			if id != nil {
				return nil, errors.New("age: multiple artifact IDs")
			}
			id = []byte(v)
		case []byte:
			if id != nil {
				return nil, errors.New("age: multiple artifact IDs")
			}
			id = slices.Clone(v)
		default:
			return nil, fmt.Errorf("age: unsupported artifact ID type %T", arg)
		}
	}
	return id, nil
}

type countingReader struct {
	r io.Reader
	n int64
}

func (r *countingReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	r.n += int64(n)
	return n, err
}
