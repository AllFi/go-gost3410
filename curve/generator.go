package curve

import (
	"crypto/elliptic"
	"math/big"

	"github.com/AllFi/go-gost3410/hash"
)

type Generator struct {
	Point
}

func NewGenerator(curve elliptic.Curve, seed []byte) (generator *Generator, err error) {
	a := new(big.Int).Sub(curve.Params().P, big.NewInt(3))
	b := curve.Params().B
	p := curve.Params().P

	x := hash.Calculate(seed, curve)
	for ; true; x = hash.Calculate(x.Bytes(), curve) {
		x3 := big.NewInt(0).Mul(x, big.NewInt(0).Mul(x, x))
		ax := big.NewInt(0).Mul(a, x)
		y2 := big.NewInt(0).Add(x3, big.NewInt(0).Add(ax, b))
		y2.Mod(y2, p)
		y := big.NewInt(0).ModSqrt(y2, p)
		if y == nil {
			continue
		}

		generator := &Generator{Point{x.Mod(x, p), y.Mod(y, p)}}
		return generator, nil
	}
	return
}

func GeneratorG(curve elliptic.Curve) (generator *Generator) {
	return &Generator{Point{curve.Params().Gx, curve.Params().Gy}}
}

func GeneratorH(curve elliptic.Curve) (generator *Generator, err error) {
	return NewGenerator(curve, GeneratorG(curve).Raw(curve))
}
