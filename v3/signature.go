package v3

import (
	"crypto/ecdsa"
	"fmt"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/miguelmota/go-solidity-sha3"
)

func SignMessage(privateKey *ecdsa.PrivateKey, data ...interface{}) (string, error) {
	message := solsha3.SoliditySHA3(data...)
	hash := crypto.Keccak256Hash([]byte(fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(message), message)))
	signatureBytes, err := crypto.Sign(hash.Bytes(), privateKey)
	if err != nil {
		return "", err
	}
	signatureBytes[64] += 27
	return hexutil.Encode(signatureBytes), nil
}

func VerifySignature(sign string) error {
	panic("implement me")
}
