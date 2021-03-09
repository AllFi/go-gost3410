package curve

import (
	"crypto/elliptic"
	"encoding/hex"
)

type Generator struct {
	*Point
}

func NewGenerator(curve elliptic.Curve, seed []byte) (generator *Generator) {
	point, _ := MapToGroup(curve, hex.EncodeToString(seed))
	return &Generator{point}
}

func GeneratorG(curve elliptic.Curve) (generator *Generator) {
	return &Generator{&Point{curve.Params().Gx, curve.Params().Gy}}
}

func GeneratorH(curve elliptic.Curve) (generator *Generator) {
	return NewGenerator(curve, GeneratorG(curve).Bytes(curve))
}
