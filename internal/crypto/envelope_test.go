package crypto

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"
)

func TestEncryptDecryptEnvelope_RoundTrip(t *testing.T) {
	dek := randomBytes(t, DEKSizeBytes)
	plaintext := []byte("classified payroll document")
	aad := []byte("tenant=acme|record=550e8400-e29b-41d4-a716-446655440000")

	env, err := EncryptEnvelope(plaintext, dek, aad)
	if err != nil {
		t.Fatalf("EncryptEnvelope() error = %v", err)
	}

	got, err := DecryptEnvelope(env, dek, aad)
	if err != nil {
		t.Fatalf("DecryptEnvelope() error = %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("plaintext mismatch: got %q, want %q", got, plaintext)
	}
}

func TestEncryptEnvelope_InvalidDEKSize(t *testing.T) {
	_, err := EncryptEnvelope([]byte("data"), make([]byte, 31), []byte("aad"))
	if !errors.Is(err, ErrInvalidDEKSize) {
		t.Fatalf("expected ErrInvalidDEKSize, got %v", err)
	}
}

func TestDecryptEnvelope_AADHashMismatch(t *testing.T) {
	dek := randomBytes(t, DEKSizeBytes)
	env, err := EncryptEnvelope([]byte("data"), dek, []byte("aad-1"))
	if err != nil {
		t.Fatalf("EncryptEnvelope() error = %v", err)
	}

	_, err = DecryptEnvelope(env, dek, []byte("aad-2"))
	if !errors.Is(err, ErrAADHashMismatch) {
		t.Fatalf("expected ErrAADHashMismatch, got %v", err)
	}
}

func TestDecryptEnvelope_TamperedCiphertext(t *testing.T) {
	dek := randomBytes(t, DEKSizeBytes)
	env, err := EncryptEnvelope([]byte("vault data"), dek, []byte("aad"))
	if err != nil {
		t.Fatalf("EncryptEnvelope() error = %v", err)
	}
	env.Ciphertext[0] ^= 0x01

	_, err = DecryptEnvelope(env, dek, []byte("aad"))
	if err == nil {
		t.Fatal("expected decryption failure for tampered ciphertext")
	}
}

func TestDecryptEnvelope_InvalidNonce(t *testing.T) {
	dek := randomBytes(t, DEKSizeBytes)
	env := Envelope{
		Ciphertext: []byte("not-a-real-ciphertext"),
		Nonce:      make([]byte, NonceSizeBytes-1),
		AADHash:    randomBytes(t, 32),
	}

	_, err := DecryptEnvelope(env, dek, []byte("aad"))
	if !errors.Is(err, ErrInvalidNonce) {
		t.Fatalf("expected ErrInvalidNonce, got %v", err)
	}
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand.Read() error = %v", err)
	}
	return b
}
