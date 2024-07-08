package walletsignature

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"github.com/ethereum/go-ethereum/crypto"
)

// GenerateKey generates a new private key and returns its hex representation and the corresponding public key address.
func GenerateKey() (privateKey string, publicKey string, err error) {
	var ecdsaPrivateKey *ecdsa.PrivateKey
	if ecdsaPrivateKey, err = crypto.GenerateKey(); err != nil {
		return "", "", fmt.Errorf("Failed to generate private key: %v ", err)
	}

	privateKeyHex := crypto.FromECDSA(ecdsaPrivateKey)
	cryptoPublicKey := ecdsaPrivateKey.Public()
	publicKeyECDSA, ok := cryptoPublicKey.(*ecdsa.PublicKey)
	if !ok {
		return "", "", fmt.Errorf("Error casting public key to ECDSA ")
	}

	return hex.EncodeToString(privateKeyHex), crypto.PubkeyToAddress(*publicKeyECDSA).String(), nil
}
