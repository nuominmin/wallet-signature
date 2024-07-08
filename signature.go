/*
Package walletsignature provides functions to generate ECDSA keys, sign messages using EIP-712, and verify signatures.

This package is designed to be used for Ethereum-based cryptographic operations.

Usage: ./signature_test.go
*/
package walletsignature

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
	"strings"
)

// primaryType is the default primary type for the EIP-712 message
var primaryType = "Message"

// SetPrimaryType sets the primary type for the EIP-712 message
func SetPrimaryType(newPrimaryType string) {
	primaryType = newPrimaryType
}

// Generate the types for EIP712Domain based on the domain struct
func genDomainFields(domain apitypes.TypedDataDomain) []apitypes.Type {
	domainFields := make([]apitypes.Type, 0)
	if domain.ChainId != nil {
		domainFields = append(domainFields, apitypes.Type{Name: "chainId", Type: "uint256"})
	}
	if domain.Name != "" {
		domainFields = append(domainFields, apitypes.Type{Name: "name", Type: "string"})
	}
	if domain.Version != "" {
		domainFields = append(domainFields, apitypes.Type{Name: "version", Type: "string"})
	}
	if domain.VerifyingContract != "" {
		domainFields = append(domainFields, apitypes.Type{Name: "verifyingContract", Type: "address"})
	}
	if domain.Salt != "" {
		domainFields = append(domainFields, apitypes.Type{Name: "salt", Type: "bytes32"})
	}
	return domainFields
}

// Generate the types for the primary type based on the messages
func genPrimaryTypeFields(messages apitypes.TypedDataMessage) ([]apitypes.Type, error) {
	primaryTypeFields := make([]apitypes.Type, 0)
	for key, value := range messages {
		var fieldType string
		switch value.(type) {
		case int, int64, uint, uint64:
			fieldType = "uint256"
		case string:
			fieldType = "string"
		case []byte:
			fieldType = "bytes"
		case bool:
			fieldType = "bool"
		default:
			return nil, fmt.Errorf("unsupported message field type for key: %s", key)
		}
		primaryTypeFields = append(primaryTypeFields, apitypes.Type{Name: key, Type: fieldType})
	}
	return primaryTypeFields, nil
}

// SignMessage signs a message using the given private key hex, chain ID, and messages.
func SignMessage(privateHexKey string, domain apitypes.TypedDataDomain, messages apitypes.TypedDataMessage) (string, error) {
	privateKey, err := crypto.HexToECDSA(privateHexKey)
	if err != nil {
		return "", fmt.Errorf("failed to load private key: %v", err)
	}

	var primaryTypeFields []apitypes.Type
	if primaryTypeFields, err = genPrimaryTypeFields(messages); err != nil {
		return "", err
	}

	typedData := apitypes.TypedData{
		Types: map[string][]apitypes.Type{
			"EIP712Domain": genDomainFields(domain),
			primaryType:    primaryTypeFields,
		},
		PrimaryType: primaryType,
		Domain:      domain,
		Message:     messages,
	}

	domainSeparator, err := typedData.HashStruct("EIP712Domain", typedData.Domain.Map())
	if err != nil {
		return "", fmt.Errorf("failed to hash domain: %v", err)
	}

	typedDataHash, err := typedData.HashStruct(primaryType, typedData.Message)
	if err != nil {
		return "", fmt.Errorf("failed to hash message: %v", err)
	}

	data := append([]byte("\x19\x01"), domainSeparator...)
	data = append(data, typedDataHash...)

	signature, err := crypto.Sign(crypto.Keccak256(data), privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign data: %v", err)
	}

	if signature[64] < 27 {
		signature[64] += 27
	}

	return "0x" + hex.EncodeToString(signature), nil
}

// VerifySignature verifies the signature for the given message parameters.
func VerifySignature(sign string, address string, domain apitypes.TypedDataDomain, messages map[string]interface{}) error {
	if len(sign) == 0 || !strings.HasPrefix(strings.ToLower(sign), "0x") {
		return InvalidSignFormatErr
	}

	sig, err := hex.DecodeString(strings.TrimPrefix(sign, "0x"))
	if err != nil {
		return InvalidHexStringErr
	}

	if len(sig) != 65 {
		return NotOfProperLengthErr
	}

	var primaryTypeFields []apitypes.Type
	if primaryTypeFields, err = genPrimaryTypeFields(messages); err != nil {
		return err
	}

	authData := apitypes.TypedData{
		Types: map[string][]apitypes.Type{
			"EIP712Domain": genDomainFields(domain),
			primaryType:    primaryTypeFields,
		},
		PrimaryType: primaryType,
		Domain:      domain,
		Message:     messages,
	}

	var pubKey string
	if pubKey, err = verifyAuthTokenAddress(authData, sign); err != nil {
		return err
	}

	if strings.ToLower(pubKey) != strings.ToLower(address) {
		return SignatureNotMatchErr
	}

	return nil
}

func verifyAuthTokenAddress(authToken apitypes.TypedData, sign string) (string, error) {
	signature, err := hexutil.Decode(sign)
	if err != nil {
		return "", fmt.Errorf("decode signature: %w", err)
	}

	typedDataBytes, err := json.MarshalIndent(authToken, "", "    ")
	if err != nil {
		return "", fmt.Errorf("marshal indent data: %w", err)
	}

	var typedData apitypes.TypedData
	err = json.Unmarshal(typedDataBytes, &typedData)
	if err != nil {
		return "", fmt.Errorf("unmarshal typed data: %w", err)
	}

	domainSeparator, err := typedData.HashStruct("EIP712Domain", typedData.Domain.Map())
	if err != nil {
		return "", fmt.Errorf("eip712domain hash struct: %w", err)
	}

	typedDataHash, err := typedData.HashStruct(typedData.PrimaryType, typedData.Message)
	if err != nil {
		return "", fmt.Errorf("primary type hash struct: %w", err)
	}

	rawData := []byte(fmt.Sprintf("\x19\x01%s%s", string(domainSeparator), string(typedDataHash)))
	sigHash := crypto.Keccak256(rawData)

	signature[64] -= 27

	sigPubKey, err := crypto.Ecrecover(sigHash, signature)
	if err != nil {
		return "", fmt.Errorf("ecrecover: %w", err)
	}

	pubKey, err := crypto.UnmarshalPubkey(sigPubKey)
	if err != nil {
		return "", fmt.Errorf("unmarshal Pubkey: %w", err)
	}
	return crypto.PubkeyToAddress(*pubKey).Hex(), nil
}
