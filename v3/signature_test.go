package v3

import (
	"fmt"
	"github.com/ethereum/go-ethereum/crypto"
	walletsignature "github.com/nuominmin/wallet-signature"
	"github.com/shopspring/decimal"
	"github.com/stretchr/testify/suite"
	"testing"
)

var txHash = "0x10a168b7c1d4a3a716a9198d23cd03e5e9373ebc1cfdb83935d250c287ada190"
var amt = decimal.NewFromFloat(200.1).Mul(decimal.NewFromInt(1e8))
var from = "0x0000E3E55554Affb68617C09D9564EeFC28A2222"
var to = "0xFdcF1Be325F7036Ca9125faa96efb539757B03b6"
var tick = "0x65746869"
var privateKey string
var publicKey string

func TestSignature(t *testing.T) {
	suite.Run(t, new(TestSignatureSuite))
}

type TestSignatureSuite struct {
	suite.Suite
}

func (s *TestSignatureSuite) SetupSuite() {

}

func (s *TestSignatureSuite) TestGenKey() {
	privateKey, publicKey, _ = walletsignature.GenerateKey()
}

func (s *TestSignatureSuite) TestSignature() {
	ecdsaPrivateKey, err := crypto.HexToECDSA(privateKey)
	if err != nil {
		s.Error(err)
		return
	}

	// 签名的数据类型
	dataTypes := []string{"address", "uint256", "address", "address", "address"}

	var sign string
	if sign, err = SignMessage(ecdsaPrivateKey, dataTypes, txHash, amt.String(), from, to, tick); err != nil {
		s.Error(err)
		return
	}

	fmt.Println("sign", sign)
}
