package usb

import (
	"fmt"
	"os"
)

// KeyOffset is the sector offset where the encrypted SSH key is stored.
// Placed after magic bytes, at sector 2049.
const KeyOffset = int64(2049) * 512

// KeySize is the maximum size of the stored encrypted key blob (bytes).
// 4096 bytes is plenty for an encrypted ed25519 or RSA key.
const KeySize = 4096

// LenOffset stores a 4-byte little-endian length prefix before the key blob.
const LenOffset = KeyOffset - 4

// ReadEncryptedKey reads the encrypted SSH key blob from raw sectors.
func ReadEncryptedKey(devicePath string) ([]byte, error) {
	if usesFiles(devicePath) {
		return fileReadKey(devicePath)
	}
	f, err := os.OpenFile(devicePath, os.O_RDONLY, 0)
	if err != nil {
		return nil, fmt.Errorf("opening device %s: %w", devicePath, err)
	}
	defer f.Close()

	// Read 4-byte length prefix
	lenBuf := make([]byte, 4)
	if _, err := f.ReadAt(lenBuf, LenOffset); err != nil {
		return nil, fmt.Errorf("reading key length: %w", err)
	}

	keyLen := int(lenBuf[0]) | int(lenBuf[1])<<8 | int(lenBuf[2])<<16 | int(lenBuf[3])<<24
	if keyLen <= 0 || keyLen > KeySize {
		return nil, fmt.Errorf("invalid key length in device: %d", keyLen)
	}

	// Read key blob
	blob := make([]byte, keyLen)
	if _, err := f.ReadAt(blob, KeyOffset); err != nil {
		return nil, fmt.Errorf("reading key blob: %w", err)
	}

	return blob, nil
}

// WriteEncryptedKey writes an encrypted SSH key blob to raw sectors.
// Used by cryptclient-init during USB stick setup.
func WriteEncryptedKey(devicePath string, blob []byte) error {
	if usesFiles(devicePath) {
		return fileWriteKey(devicePath, blob)
	}
	if len(blob) > KeySize {
		return fmt.Errorf("key blob too large: %d bytes (max %d)", len(blob), KeySize)
	}

	f, err := os.OpenFile(devicePath, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("opening device %s for write: %w", devicePath, err)
	}
	defer f.Close()

	// Write magic bytes
	if _, err := f.WriteAt(MagicBytes, MagicOffset); err != nil {
		return fmt.Errorf("writing magic bytes: %w", err)
	}

	// Write 4-byte length prefix (little-endian)
	l := len(blob)
	lenBuf := []byte{byte(l), byte(l >> 8), byte(l >> 16), byte(l >> 24)}
	if _, err := f.WriteAt(lenBuf, LenOffset); err != nil {
		return fmt.Errorf("writing key length: %w", err)
	}

	// Write key blob
	if _, err := f.WriteAt(blob, KeyOffset); err != nil {
		return fmt.Errorf("writing key blob: %w", err)
	}

	// Sync to ensure data is flushed to device
	return f.Sync()
}
