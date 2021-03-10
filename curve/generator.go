package curve

import (
	"crypto/elliptic"
	"encoding/hex"

	"github.com/AllFi/go-gost3410"
)

type Generator struct {
	*Point
}

func NewGenerator(curve elliptic.Curve, ha gost3410.HashAlgorithm, seed []byte) (generator *Generator) {
	point, _ := MapToGroup(curve, ha, hex.EncodeToString(seed))
	return &Generator{point}
}

func GeneratorG(curve elliptic.Curve) (generator *Generator) {
	return &Generator{&Point{curve.Params().Gx, curve.Params().Gy}}
}

func GeneratorH(curve elliptic.Curve, ha gost3410.HashAlgorithm) (generator *Generator) {
	return NewGenerator(curve, ha, GeneratorG(curve).Bytes(curve))
}
