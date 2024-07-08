package walletsignature

import (
	"fmt"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
	"github.com/stretchr/testify/suite"
	"testing"
	"time"
)

var chainId int64 = 11155111

var privateKey string
var publicKey string

var sign string
var nonce int64

func TestSignature(t *testing.T) {
	suite.Run(t, new(TestSignatureSuite))
}

type TestSignatureSuite struct {
	suite.Suite
}

func (s *TestSignatureSuite) SetupSuite() {

}

func (s *TestSignatureSuite) TestGenKey() {
	privateKey, publicKey, _ = GenerateKey()
}

// 签名
func (s *TestSignatureSuite) TestSignature() {
	var err error
	nonce = time.Now().Unix()
	sign, err = SignMessage(privateKey,
		apitypes.TypedDataDomain{ChainId: math.NewHexOrDecimal256(chainId)},
		map[string]interface{}{
			"nonce": fmt.Sprintf("%d", nonce),
		},
	)
	if err != nil {
		s.Error(err)
		return
	}
}

// 验签
func (s *TestSignatureSuite) TestSignatureVerify() {
	err := VerifySignature(sign,
		publicKey,
		apitypes.TypedDataDomain{ChainId: math.NewHexOrDecimal256(chainId)},
		map[string]interface{}{
			"nonce": fmt.Sprintf("%d", nonce),
		},
	)
	if err != nil {
		fmt.Printf("\nsign: %s\nnonce: %d\naddress: %s\nerror: %s\n\n", sign, nonce, publicKey, err.Error())

		s.Error(err, "verify error")
		return
	}

	fmt.Printf("\nsign: %s\nnonce: %d\naddress: %s\n\n", sign, nonce, publicKey)
}
