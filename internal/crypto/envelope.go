package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
)

const (
	// DEKSizeBytes is the required key size for AES-256.
	DEKSizeBytes = 32
	// NonceSizeBytes is the standard nonce size for GCM.
	NonceSizeBytes = 12
)

var (
	ErrInvalidDEKSize  = errors.New("invalid DEK size: expected 32 bytes")
	ErrInvalidNonce    = errors.New("invalid nonce size")
	ErrAADHashMismatch = errors.New("aad hash mismatch")
)

// Envelope holds encrypted data and metadata needed to verify and decrypt.
type Envelope struct {
	Ciphertext []byte
	Nonce      []byte
	AADHash    []byte
}

// EncryptEnvelope encrypts plaintext using AES-256-GCM and returns a transport-safe envelope.
func EncryptEnvelope(plaintext, dek, aad []byte) (Envelope, error) {
	if len(dek) != DEKSizeBytes {
		return Envelope{}, ErrInvalidDEKSize
	}

	block, err := aes.NewCipher(dek)
	if err != nil {
		return Envelope{}, fmt.Errorf("create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return Envelope{}, fmt.Errorf("create GCM: %w", err)
	}

	nonce := make([]byte, NonceSizeBytes)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return Envelope{}, fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, aad)
	aadHash := sha256.Sum256(aad)

	return Envelope{
		Ciphertext: cloneBytes(ciphertext),
		Nonce:      cloneBytes(nonce),
		AADHash:    cloneBytes(aadHash[:]),
	}, nil
}

// DecryptEnvelope verifies metadata and decrypts ciphertext using AES-256-GCM.
func DecryptEnvelope(envelope Envelope, dek, aad []byte) ([]byte, error) {
	if len(dek) != DEKSizeBytes {
		return nil, ErrInvalidDEKSize
	}
	if len(envelope.Nonce) != NonceSizeBytes {
		return nil, fmt.Errorf("%w: expected %d bytes, got %d", ErrInvalidNonce, NonceSizeBytes, len(envelope.Nonce))
	}

	expectedAADHash := sha256.Sum256(aad)
	if !equalBytes(envelope.AADHash, expectedAADHash[:]) {
		return nil, ErrAADHashMismatch
	}

	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("create AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	plaintext, err := gcm.Open(nil, envelope.Nonce, envelope.Ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("decrypt envelope: %w", err)
	}

	return cloneBytes(plaintext), nil
}

func cloneBytes(in []byte) []byte {
	if in == nil {
		return nil
	}
	out := make([]byte, len(in))
	copy(out, in)
	return out
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}
