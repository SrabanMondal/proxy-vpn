package crypto

import (
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	//"log"

	"github.com/SrabanMondal/proxy-vpn/internal/pool"
	"golang.org/x/crypto/chacha20poly1305"
)

// ChaCha20Crypto implements AEAD encryption using XChaCha20-Poly1305.
// Format:
//   finalCiphertext = nonce(24b) | DATA |  Poly1305 Tag (16b).
type ChaCha20Crypto struct {
    aead cipher.AEAD
}


// NewChaCha20Crypto creates an XChaCha20-Poly1305 instance.
func NewChaCha20Crypto(key []byte) (*ChaCha20Crypto, error) {
    if len(key) != chacha20poly1305.KeySize {
        return nil, errors.New("chacha20: key must be 32 bytes")
    }

    aead, err := chacha20poly1305.NewX(key)
    if err != nil {
        return nil, err
    }

    return &ChaCha20Crypto{
        aead: aead,
    }, nil
}

// Encrypt performs in-place encryption
func (c *ChaCha20Crypto) Encrypt(plainBuf, plaintext []byte) ([]byte, error) {
    encBuf := pool.Get()
    required := 24 + len(plaintext) + c.aead.Overhead()
    // log.Printf("Encry temporary buffer (len-%d) and required: %d",len(encBuf), required)
    if required > len(encBuf) {
        pool.Put(encBuf)
        return nil, fmt.Errorf("encBuf too small: need %d bytes", required)
    }
    nonce := encBuf[:24]
    if _, err := rand.Read(nonce); err != nil {
        pool.Put(encBuf)
        return nil, err
    }

    cipherDst := encBuf[24 : required : len(encBuf)]

    cipherBody := c.aead.Seal(cipherDst[:0], nonce, plaintext, nil)

    total := 24 + len(cipherBody)
    copy(plainBuf, encBuf[:total])
    pool.Put(encBuf)

    return plainBuf[:total], nil
}

// Decrypt performs in-place decryption.
func (c *ChaCha20Crypto) Decrypt(ciphertext []byte) ([]byte, error) {
    if len(ciphertext) < chacha20poly1305.NonceSizeX+c.aead.Overhead() {
        return nil, errors.New("chacha20: ciphertext too short")
    }

    nonce := ciphertext[:chacha20poly1305.NonceSizeX]
    enc := ciphertext[chacha20poly1305.NonceSizeX:]

    return c.aead.Open(enc[:0], nonce, enc, nil)
}
