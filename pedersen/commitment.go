package pedersen

import (
	"math/big"

	"github.com/AllFi/go-gost3410"
	"github.com/AllFi/go-gost3410/curve"
	"github.com/pkg/errors"
)

type Commitment struct {
	*curve.Point
}

func NewCommitment(context *gost3410.Context, value uint64, blind []byte, h *curve.Generator, g *curve.Generator) (commitment *Commitment) {
	// v * h + b * G
	c := context.Curve
	v := new(big.Int).SetUint64(value)
	b := new(big.Int).SetBytes(blind)

	x1, y1 := c.ScalarMult(h.X, h.Y, v.Bytes())
	x2, y2 := c.ScalarMult(g.X, g.Y, b.Bytes())
	x, y := c.Add(x1, y1, x2, y2)
	return &Commitment{&curve.Point{x, y}}
}

func CommitSum(context *gost3410.Context, positive []*Commitment, negative []*Commitment) (commit *Commitment) {
	c := context.Curve
	x, y := new(big.Int), new(big.Int)

	for _, commit := range positive {
		x, y = c.Add(x, y, commit.X, commit.Y)
	}

	for _, commit := range negative {
		x, y = c.Add(x, y, commit.X, new(big.Int).Neg(commit.Y))
	}
	return &Commitment{&curve.Point{x, y}}
}

func CommitFromString(context *gost3410.Context, s string) (c *Commitment, err error) {
	p, err := curve.PointFromHex(context.Curve, s)
	if err != nil {
		err = errors.Wrap(err, "cannot PointFromHex")
		return
	}
	return &Commitment{p}, nil
}

func (c *Commitment) String(context *gost3410.Context) string {
	return c.Point.Hex(context.Curve)
}
