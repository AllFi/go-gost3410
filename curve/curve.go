package curve

import (
	"crypto/elliptic"
	"math/big"
)

var gost34102001 *elliptic.CurveParams

func init() {
	initGOST34102001()
}

func initGOST34102001() {
	// CurveParamsGostR34102001CryptoProA
	gost34102001 = &elliptic.CurveParams{Name: "GOST R 34.10 CryptoProA"}
	gost34102001.P, _ = new(big.Int).SetString("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd97", 16)
	gost34102001.N, _ = new(big.Int).SetString("ffffffffffffffffffffffffffffffff6c611070995ad10045841b09b761b893", 16)
	// a = -3
	gost34102001.B, _ = new(big.Int).SetString("00000000000000000000000000000000000000000000000000000000000000a6", 16)
	gost34102001.Gx, _ = new(big.Int).SetString("0000000000000000000000000000000000000000000000000000000000000001", 16)
	gost34102001.Gy, _ = new(big.Int).SetString("8d91e471e0989cda27df505a453f2b7635294f2ddf23e3b122acc99c9e9f1e14", 16)
	gost34102001.BitSize = 256
}

func GOST34102001() elliptic.Curve {
	return gost34102001
}
