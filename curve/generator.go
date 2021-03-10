package curve

import (
	"encoding/hex"

	"github.com/AllFi/go-gost3410"
)

type Generator struct {
	*Point
}

func NewGenerator(context *gost3410.Context, seed []byte) (generator *Generator) {
	point, _ := MapToGroup(context.Curve, context.HashAlgorithm, hex.EncodeToString(seed))
	return &Generator{point}
}

func GeneratorG(context *gost3410.Context) (generator *Generator) {
	return &Generator{&Point{context.Curve.Params().Gx, context.Curve.Params().Gy}}
}

func GeneratorH(context *gost3410.Context) (generator *Generator) {
	return NewGenerator(context, GeneratorG(context).Bytes(context.Curve))
}
