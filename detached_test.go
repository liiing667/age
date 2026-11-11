package age_test

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"filippo.io/age"
	"filippo.io/age/internal/format"
)

const fixtureNonceSize = 16

func encryptDetachedFixture(t *testing.T, identity *age.X25519Identity, plaintext string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, identity.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(w, plaintext); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func ciphertextMetadata(t *testing.T, encrypted []byte) (header []byte, headerLen int, nonce []byte, payloadSize int64) {
	t.Helper()
	hdr, payload, err := format.Parse(bytes.NewReader(encrypted))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := hdr.Marshal(&buf); err != nil {
		t.Fatal(err)
	}
	header = buf.Bytes()

	var n [fixtureNonceSize]byte
	if _, err := io.ReadFull(payload, n[:]); err != nil {
		t.Fatal(err)
	}
	rest, err := io.ReadAll(payload)
	if err != nil {
		t.Fatal(err)
	}
	return header, buf.Len(), n[:], int64(len(rest))
}

func TestHeaderBindingRoundTrip(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	encrypted := encryptDetachedFixture(t, identity, helloWorld)

	header, binding, err := age.ExtractHeaderBinding(bytes.NewReader(encrypted), "artifact-A")
	if err != nil {
		t.Fatal(err)
	}
	if got := string(binding.ArtifactID); got != "artifact-A" {
		t.Fatalf("wrong artifact ID: %q", got)
	}
	canonicalHeader, err := age.ExtractHeader(bytes.NewReader(encrypted))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(header, canonicalHeader) {
		t.Fatal("binding extraction changed the detached header")
	}
	fingerprint, err := age.HeaderFingerprint(header)
	if err != nil {
		t.Fatal(err)
	}
	if fingerprint != binding.Fingerprint {
		t.Fatal("binding fingerprint does not match the detached header")
	}

	constructed, err := age.NewHeaderBinding(header, binding.Nonce[:], binding.PayloadSize, "artifact-A")
	if err != nil {
		t.Fatal(err)
	}
	if constructed.Fingerprint != binding.Fingerprint ||
		constructed.Nonce != binding.Nonce ||
		constructed.PayloadSize != binding.PayloadSize ||
		!bytes.Equal(constructed.ArtifactID, binding.ArtifactID) {
		t.Fatal("NewHeaderBinding produced a different binding")
	}

	encoded, err := binding.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := age.ParseHeaderBinding(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Fingerprint != binding.Fingerprint ||
		parsed.Nonce != binding.Nonce ||
		parsed.PayloadSize != binding.PayloadSize ||
		!bytes.Equal(parsed.ArtifactID, binding.ArtifactID) {
		t.Fatal("binding binary round trip changed fields")
	}

	fileKey, err := age.DecryptHeaderBinding(header, parsed, "artifact-A", identity)
	if err != nil {
		t.Fatal(err)
	}
	out, err := age.Decrypt(bytes.NewReader(encrypted), age.NewInjectedFileKeyIdentity(fileKey))
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := io.ReadAll(out)
	if err != nil {
		t.Fatal(err)
	}
	if string(plaintext) != helloWorld {
		t.Fatalf("wrong plaintext: %q", plaintext)
	}
	if _, err := age.DecryptHeaderBinding(header, binding, "artifact-B", identity); !errors.Is(err, age.ErrHeaderBindingMismatch) {
		t.Fatalf("wrong artifact ID was accepted: %v", err)
	}

	fileKey2, err := age.DecryptHeaderBindingForCiphertext(header, binding, bytes.NewReader(encrypted), "artifact-A", identity)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(fileKey, fileKey2) {
		t.Fatal("ciphertext-verified decryption returned a different file key")
	}

	atHeader, atBinding, err := age.ExtractHeaderBindingAt(bytes.NewReader(encrypted), int64(len(encrypted)), "artifact-A")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(atHeader, header) || atBinding.PayloadSize != binding.PayloadSize ||
		atBinding.Nonce != binding.Nonce || atBinding.Fingerprint != binding.Fingerprint {
		t.Fatal("ExtractHeaderBindingAt produced a different binding")
	}
}

func TestHeaderBindingRejectsSwappedHeaders(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	encryptedA := encryptDetachedFixture(t, identity, "file A")
	encryptedB := encryptDetachedFixture(t, identity, "a different file B")

	headerA, bindingA, err := age.ExtractHeaderBinding(bytes.NewReader(encryptedA))
	if err != nil {
		t.Fatal(err)
	}
	headerB, bindingB, err := age.ExtractHeaderBinding(bytes.NewReader(encryptedB))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(headerA, headerB) || bindingA.Fingerprint == bindingB.Fingerprint {
		t.Fatal("fixtures unexpectedly have identical headers")
	}

	if _, err := age.DecryptHeaderBinding(headerB, bindingA, identity); !errors.Is(err, age.ErrHeaderBindingMismatch) {
		t.Fatalf("swapped header was accepted: %v", err)
	}
	if _, err := age.DecryptHeaderBinding(headerA, bindingB, identity); !errors.Is(err, age.ErrHeaderBindingMismatch) {
		t.Fatalf("swapped binding was accepted: %v", err)
	}
	if err := age.VerifyHeaderBinding(headerB, bindingA); !errors.Is(err, age.ErrHeaderBindingMismatch) {
		t.Fatalf("swapped header passed verification: %v", err)
	}

	_, _, nonceA, payloadSizeA := ciphertextMetadata(t, encryptedA)
	_, _, nonceB, payloadSizeB := ciphertextMetadata(t, encryptedB)
	if err := age.VerifyHeaderBindingCiphertext(headerA, bindingA, nonceA, payloadSizeA); err != nil {
		t.Fatalf("correct ciphertext metadata was rejected: %v", err)
	}
	if _, err := age.DecryptHeaderBindingCiphertext(headerA, bindingA, nonceB, payloadSizeB, identity); !errors.Is(err, age.ErrHeaderBindingMismatch) {
		t.Fatalf("binding was accepted for another ciphertext: %v", err)
	}
	if _, err := age.DecryptHeaderBinding(headerA, bindingA, bytes.NewReader(encryptedB), identity); !errors.Is(err, age.ErrHeaderBindingMismatch) {
		t.Fatalf("binding was accepted for another ciphertext reader: %v", err)
	}
}

func TestHeaderBindingRejectsUnboundAndMultiple(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	encryptedA := encryptDetachedFixture(t, identity, "file A")
	encryptedB := encryptDetachedFixture(t, identity, "file B")

	header, binding, err := age.ExtractHeaderBinding(bytes.NewReader(encryptedA))
	if err != nil {
		t.Fatal(err)
	}

	for _, binding := range []any{nil, age.HeaderBinding{}, []byte{}, (*age.HeaderBinding)(nil)} {
		if _, err := age.DecryptHeaderBinding(header, binding, identity); !errors.Is(err, age.ErrUnboundHeader) {
			t.Fatalf("unbound header %#v was not rejected with ErrUnboundHeader: %v", binding, err)
		}
	}

	headerB, _, err := age.ExtractHeaderBinding(bytes.NewReader(encryptedB))
	if err != nil {
		t.Fatal(err)
	}
	multiple := append(append([]byte{}, header...), headerB...)
	if _, err := age.DecryptHeaderBinding(multiple, binding, identity); !errors.Is(err, age.ErrMultipleHeaders) {
		t.Fatalf("concatenated headers were accepted: %v", err)
	}
	if _, err := age.HeaderFingerprint(multiple); !errors.Is(err, age.ErrMultipleHeaders) {
		t.Fatalf("fingerprint accepted concatenated headers: %v", err)
	}
	if _, _, err := age.ExtractHeaderBinding(bytes.NewReader(multiple)); !errors.Is(err, age.ErrMultipleHeaders) {
		t.Fatalf("extraction accepted concatenated headers: %v", err)
	}
}

func TestHeaderBindingRejectsTruncatedPayload(t *testing.T) {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	encrypted := encryptDetachedFixture(t, identity, helloWorld)
	header, binding, err := age.ExtractHeaderBinding(bytes.NewReader(encrypted))
	if err != nil {
		t.Fatal(err)
	}

	truncated := encrypted[:len(encrypted)-1]
	_, _, nonce, payloadSize := ciphertextMetadata(t, truncated)
	if payloadSize == binding.PayloadSize {
		t.Fatal("fixture truncation did not change the payload length")
	}
	if _, err := age.DecryptHeaderBindingCiphertext(header, binding, nonce, payloadSize, identity); !errors.Is(err, age.ErrHeaderBindingMismatch) {
		t.Fatalf("truncated payload was accepted: %v", err)
	}
	if _, err := age.DecryptHeaderBindingForCiphertext(header, binding, bytes.NewReader(truncated), identity); !errors.Is(err, age.ErrHeaderBindingMismatch) {
		t.Fatalf("truncated payload reader was accepted: %v", err)
	}

	// Reading the truncated ciphertext with the original size must fail rather
	// than producing a binding with a short payload.
	if _, _, err := age.ExtractHeaderBindingAt(bytes.NewReader(truncated), int64(len(encrypted))); err == nil {
		t.Fatal("truncated ciphertext was accepted by ExtractHeaderBindingAt")
	}
	if _, truncatedBinding, err := age.ExtractHeaderBindingAt(bytes.NewReader(truncated), int64(len(truncated))); err != nil {
		t.Fatal(err)
	} else if truncatedBinding.PayloadSize >= binding.PayloadSize {
		t.Fatal("truncated binding did not record the shorter payload")
	}
}
