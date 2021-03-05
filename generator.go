package gost3410

import (
	"crypto/sha256"
	"math/big"
)

type Generator PublicKey

func arrayToSlice(arr [32]byte) []byte {
	return arr[:]
}

func NewGenerator(context *Context, seed []byte) (generator *Generator, err error) {
	a := context.Curve.A
	b := context.Curve.B
	p := context.Curve.P

	x := big.NewInt(0).SetBytes(arrayToSlice(sha256.Sum256(seed)))
	for ; true; x = big.NewInt(0).SetBytes(arrayToSlice(sha256.Sum256(x.Bytes()))) {
		x3 := big.NewInt(0).Mul(x, big.NewInt(0).Mul(x, x))
		ax := big.NewInt(0).Mul(a, x)
		y2 := big.NewInt(0).Add(x3, big.NewInt(0).Add(ax, b))
		y2.Mod(y2, p)
		y := big.NewInt(0).ModSqrt(y2, p)
		if y == nil {
			continue
		}

		generator := (*Generator)(&PublicKey{x.Mod(x, p), y.Mod(y, p)})
		return generator, nil
	}
	panic("")
}
