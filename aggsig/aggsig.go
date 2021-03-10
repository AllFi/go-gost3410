package aggsig

import (
	"math/big"

	"github.com/AllFi/go-gost3410"
	"github.com/AllFi/go-gost3410/curve"
	"github.com/AllFi/go-gost3410/hash"
	"github.com/AllFi/go-gost3410/utils"
	"github.com/pkg/errors"
)

var (
	zero = big.NewInt(0)
)

func SignPartial(
	context *gost3410.Context,
	rawPrivateKey []byte,
	nonce []byte,
	sumNonces *PublicKey,
	msg []byte,
) (
	signature []byte,
	err error,
) {
	privateKey, err := NewPrivateKey(context, rawPrivateKey)
	if err != nil {
		err = errors.Wrap(err, "cannot NewPrivateKey")
		return
	}

	d := privateKey.Int
	k := big.NewInt(0).SetBytes(nonce)
	r := sumNonces.X
	e := hash.HashToInt(msg, context.HashAlgorithm, context.Curve)
	q := context.Curve.Params().N
	mode := context.Curve.Params().BitSize / 8

	// s = d*r + k*e mod q, where d - privateKey, k - nonce, r - x coordinate of sumNonces, e - message digest
	s := big.NewInt(0)
	s.Mod(s.Add(big.NewInt(0).Mul(d, r), big.NewInt(0).Mul(k, e)), q)
	if s.Cmp(zero) == 0 {
		err = errors.New("failed to create partial signature: s is zero")
		return
	}

	return append(
		utils.Pad(s.Bytes(), mode),
		utils.Pad(r.Bytes(), mode)...,
	), nil
}

func AggregatePartialSignatures(context *gost3410.Context, rawPartialSignatures [][]byte, sumNonces *PublicKey) (signature []byte, err error) {
	mode := context.Curve.Params().BitSize / 8
	r := sumNonces.X
	q := context.Curve.Params().N
	r.Mod(r, q)

	s := new(big.Int)
	for i := 0; i < len(rawPartialSignatures); i++ {
		si := utils.BytesToBigInt(rawPartialSignatures[i][:mode])
		s.Add(s, si)
		s.Mod(s, q)
	}

	return append(
		utils.Pad(s.Bytes(), mode),
		utils.Pad(r.Bytes(), mode)...,
	), nil
}

func Verify(context *gost3410.Context, signature []byte, publicKey *PublicKey, msg []byte) (correct bool, err error) {
	return verify(context, signature, publicKey, msg, nil)
}

func VerifyPartial(context *gost3410.Context, signature []byte, publicKey *PublicKey, publicNonce *PublicKey, msg []byte) (correct bool, err error) {
	return verify(context, signature, publicKey, msg, publicNonce.X)
}

func verify(context *gost3410.Context, signature []byte, publicKey *PublicKey, msg []byte, partialR *big.Int) (correct bool, err error) {
	mode := context.Curve.Params().BitSize / 8
	curve := context.Curve
	q := context.Curve.Params().N

	if len(signature) != 2*int(mode) {
		err = errors.New("wrong signature length")
		return
	}

	// r > 0, r < q, s > 0, s < q
	s := utils.BytesToBigInt(signature[:mode])
	r := utils.BytesToBigInt(signature[mode:])
	if r.Cmp(zero) <= 0 || r.Cmp(q) >= 0 || s.Cmp(zero) <= 0 || s.Cmp(q) >= 0 {
		return false, nil
	}

	e := hash.HashToInt(msg, context.HashAlgorithm, curve)
	v := big.NewInt(0).ModInverse(e, q)

	// z1 = s * v mod q
	z1 := big.NewInt(0).Mul(s, v)
	z1.Mod(z1, q)

	// z2 = -( r * v ) mod q
	z2 := big.NewInt(0).Mul(r, v)
	z2.Sub(q, z2.Mod(z2, q))

	// z1 * P
	p1x, p1y := curve.ScalarBaseMult(z1.Bytes())

	// z2 * Q
	q1x, q1y := curve.ScalarMult(publicKey.X, publicKey.Y, z2.Bytes())

	// C = z1 * P + z2 * Q
	p1x, p1y = curve.Add(p1x, p1y, q1x, q1y)

	R := big.NewInt(0).Mod(p1x, q)
	if partialR != nil {
		// R must be equal to partialR
		return R.Cmp(partialR) == 0, nil
	}

	// R must be equal to r
	return R.Cmp(r) == 0, nil
}

func SumPublicKeys(context *gost3410.Context, publicKeys []*PublicKey) (sum *PublicKey, err error) {
	x, y := new(big.Int), new(big.Int)
	for i := 0; i < len(publicKeys); i++ {
		x, y = context.Curve.Add(x, y, publicKeys[i].X, publicKeys[i].Y)
	}

	return &PublicKey{&curve.Point{x, y}}, nil
}
