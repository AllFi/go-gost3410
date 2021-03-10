package curve

import (
	"bytes"
	"crypto/elliptic"
	"encoding/hex"
	"math/big"
	"strconv"

	"github.com/AllFi/go-gost3410"
	gghash "github.com/AllFi/go-gost3410/hash"
	"github.com/AllFi/go-gost3410/utils"
	"github.com/ing-bank/zkrp/util/bn"
	"github.com/pkg/errors"
)

type Point struct {
	X *big.Int
	Y *big.Int
}

func (p *Point) SetInfinity() *Point {
	p.X = nil
	p.Y = nil
	return p
}

func (p *Point) IsZero() bool {
	c1 := p.X == nil || p.Y == nil
	if !c1 {
		z := new(big.Int).SetInt64(0)
		return p.X.Cmp(z) == 0 && p.Y.Cmp(z) == 0
	}
	return true
}

func (p *Point) Neg(ec elliptic.Curve, a *Point) *Point {
	// (X, Y) -> (X, X + Y)
	if a.IsZero() {
		return p.SetInfinity()
	}
	one := new(big.Int).SetInt64(1)
	mone := new(big.Int).Sub(ec.Params().N, one)
	p.ScalarMult(ec, p, mone)
	return p
}

/*
ScalarBaseMult returns the Scalar Multiplication by the base generator.
*/
func (p *Point) ScalarBaseMult(ec elliptic.Curve, n *big.Int) *Point {
	cmp := n.Cmp(big.NewInt(0))
	if cmp == 0 {
		return p.SetInfinity()
	}
	n = bn.Mod(n, ec.Params().N)
	bns := n.Bytes()
	resx, resy := ec.ScalarBaseMult(bns)
	p.X = resx
	p.Y = resy
	return p
}

func (p *Point) ScalarMult(ec elliptic.Curve, a *Point, n *big.Int) *Point {
	if a.IsZero() {
		return p.SetInfinity()
	}
	cmp := n.Cmp(big.NewInt(0))
	if cmp == 0 {
		return p.SetInfinity()
	}
	n = bn.Mod(n, ec.Params().N)
	bns := n.Bytes()
	resx, resy := ec.ScalarMult(a.X, a.Y, bns)
	p.X = resx
	p.Y = resy
	return p
}

func (p *Point) Add(ec elliptic.Curve, a, b *Point) *Point {
	if a.IsZero() {
		p.X = b.X
		p.Y = b.Y
		return p
	} else if b.IsZero() {
		p.X = a.X
		p.Y = a.Y
		return p
	}
	if a.X.Cmp(b.X) == 0 && a.Y.Cmp(b.Y) == 0 {
		resx, resy := ec.Double(a.X, a.Y)
		p.X = resx
		p.Y = resy
		return p
	}
	resx, resy := ec.Add(a.X, a.Y, b.X, b.Y)
	p.X = resx
	p.Y = resy
	return p
}

/*
MapToGroup is a hash function that returns a valid elliptic curve point given as
input a string. It is also known as hash-to-point and is used to obtain a generator
that has no discrete logarithm known relation, thus addressing the concept of
NUMS (nothing up my sleeve).
This implementation is based on the paper:
Short signatures from the Weil pairing
Boneh, Lynn and Shacham
Journal of Cryptology, September 2004, Volume 17, Issue 4, pp 297–319
*/
func MapToGroup(ec elliptic.Curve, ha gost3410.HashAlgorithm, m string) (*Point, error) {
	var (
		i      int
		buffer bytes.Buffer
	)
	i = 0
	for i < 256 {
		buffer.Reset()
		buffer.WriteString(strconv.Itoa(i))
		buffer.WriteString(m)
		x := gghash.HashToInt(buffer.Bytes(), ha, ec)
		x = bn.Mod(x, ec.Params().P)
		fx, _ := F(ec, x)
		fx = bn.Mod(fx, ec.Params().P)
		y := fx.ModSqrt(fx, ec.Params().P)
		if y != nil {
			p := &Point{X: x, Y: y}
			if p.IsOnCurve(ec) && !p.IsZero() {
				return p, nil
			}
		}
		i = i + 1
	}
	return nil, errors.New("Failed to Hash-to-point.")
}

/*
F receives a big integer x as input and return x^3 + 7 mod ORDER.
*/
func F(ec elliptic.Curve, x *big.Int) (*big.Int, error) {
	a := new(big.Int).Sub(ec.Params().P, big.NewInt(3))
	b := ec.Params().B
	p := ec.Params().P

	x3 := big.NewInt(0).Mul(x, big.NewInt(0).Mul(x, x))
	ax := big.NewInt(0).Mul(a, x)
	y2 := big.NewInt(0).Add(x3, big.NewInt(0).Add(ax, b))
	y2.Mod(y2, p)
	return y2, nil
}

func (p *Point) Bytes(curve elliptic.Curve) []byte {
	mode := curve.Params().BitSize / 8
	raw := append(
		utils.Pad(p.X.Bytes(), mode),
		utils.Pad(p.Y.Bytes(), mode)...,
	)
	return raw
}

func PointFromBytes(curve elliptic.Curve, b []byte) (p *Point, err error) {
	mode := curve.Params().BitSize / 8
	if len(b) != mode*2 {
		err = errors.New("invalid length")
		return
	}
	x, y := new(big.Int).SetBytes(b[:mode]), new(big.Int).SetBytes(b[mode:])
	return &Point{x, y}, nil
}

func (p *Point) Hex(curve elliptic.Curve) string {
	raw := p.Bytes(curve)
	return hex.EncodeToString(raw)
}

func PointFromHex(curve elliptic.Curve, s string) (p *Point, err error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		err = errors.Wrap(err, "cannot DecodeString")
		return
	}
	return PointFromBytes(curve, b)
}

/*
IsOnCurve returns TRUE if and only if p has coordinates X and Y that satisfy the
Elliptic Curve equation: y^2 = x^3 + 7.
*/
func (p *Point) IsOnCurve(ec elliptic.Curve) bool {
	return ec.IsOnCurve(p.X, p.Y)
}
