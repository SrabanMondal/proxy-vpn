package crypto

import "errors"

// Crypto defines the interface for encrypting and decrypting raw byte slices.
type Crypto interface {

    Encrypt(dst, plaintext []byte) ([]byte, error)

    Decrypt(ciphertext []byte) ([]byte, error)
}

const (
    CryptoAES    = "aes-gcm"
    CryptoChaCha = "chacha20"
)

var (
    ErrUnknownCrypto = errors.New("unknown crypto provider")
)

// cryptoInstance is the active global crypto provider.
var cryptoInstance Crypto

// SetCrypto selects the encryption provider.
func SetCrypto(name string, key []byte) error {
    switch name {

    // case CryptoAES:
    //     c, err := NewAESGCMCrypto(key)
    //     if err != nil { return err }
    //     cryptoInstance = c

    case CryptoChaCha:
        c, err := NewChaCha20Crypto(key)
        if err != nil { return err }
        cryptoInstance = c

    default:
        return ErrUnknownCrypto
    }

    return nil
}

// C returns the currently active crypto provider.
func C() Crypto {
    if cryptoInstance == nil {
        panic("crypto provider not initialized — call SetCrypto() before use")
    }
    return cryptoInstance
}
