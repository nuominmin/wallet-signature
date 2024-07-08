package walletsignature

import "errors"

var (
	SignatureNotMatchErr = errors.New("signature not match")
	InvalidSignFormatErr = errors.New("invalid sign format")
	InvalidHexStringErr  = errors.New("invalid hex string")
	NotOfProperLengthErr = errors.New("not of proper length")
)
