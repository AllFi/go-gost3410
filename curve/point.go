package curve

import (
	"crypto/elliptic"
	"math/big"

	"github.com/AllFi/go-gost3410/utils"
)

type Point struct {
	X *big.Int
	Y *big.Int
}

func (p *Point) Raw(curve elliptic.Curve) []byte {
	mode := curve.Params().BitSize / 8
	raw := append(
		utils.Pad(p.Y.Bytes(), mode),
		utils.Pad(p.X.Bytes(), mode)...,
	)
	utils.Reverse(raw)
	return raw
}
