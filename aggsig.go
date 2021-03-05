package aggsig

import (
	"math/big"

	"github.com/AllFi/go-gost3410/gost3410"
	"github.com/pkg/errors"
)

var (
	zero = big.NewInt(0)
)

func SignPartial(
	context *gost3410.Context,
	rawPrivateKey []byte,
	nonce []byte,
	sumNonces *gost3410.PublicKey,
	msg []byte,
) (
	signature []byte,
	err error,
) {
	privateKey, err := gost3410.NewPrivateKey(context, rawPrivateKey)
	if err != nil {
		err = errors.Wrap(err, "cannot NewPrivateKey")
		return
	}

	d := privateKey.Key
	k := big.NewInt(0).SetBytes(nonce)
	r := sumNonces.X
	e := gost3410.СalculateDigest(msg, context.Curve)

	// s = d*r + k*e mod q, where d - privateKey, k - nonce, r - x coordinate of sumNonces, e - message digest
	s := big.NewInt(0)
	s.Mod(s.Add(big.NewInt(0).Mul(d, r), big.NewInt(0).Mul(k, e)), context.Curve.Q)
	if s.Cmp(zero) == 0 {
		err = errors.New("failed to create partial signature: s is zero")
		return
	}

	return append(
		gost3410.Pad(s.Bytes(), int(context.Mode)),
		gost3410.Pad(r.Bytes(), int(context.Mode))...,
	), nil
}

func AggregatePartialSignatures(context *gost3410.Context, rawPartialSignatures [][]byte, sumNonces *gost3410.PublicKey) (signature []byte, err error) {
	s := gost3410.BytesToBigInt(rawPartialSignatures[0][:context.Mode])
	r := sumNonces.X
	r.Mod(r, context.Curve.Q)
	for i := 1; i < len(rawPartialSignatures); i++ {
		si := gost3410.BytesToBigInt(rawPartialSignatures[i][:context.Mode])
		s.Add(s, si)
		s.Mod(s, context.Curve.Q)
	}

	return append(
		gost3410.Pad(s.Bytes(), int(context.Mode)),
		gost3410.Pad(r.Bytes(), int(context.Mode))...,
	), nil
}

func Verify(context *gost3410.Context, signature []byte, publicKey *gost3410.PublicKey, msg []byte) (correct bool, err error) {
	return verify(context, signature, publicKey, msg, nil)
}

func VerifyPartial(context *gost3410.Context, signature []byte, publicKey *gost3410.PublicKey, publicNonce *gost3410.PublicKey, msg []byte) (correct bool, err error) {
	return verify(context, signature, publicKey, msg, publicNonce.X)
}

func verify(context *gost3410.Context, signature []byte, publicKey *gost3410.PublicKey, msg []byte, partialR *big.Int) (correct bool, err error) {
	curve := context.Curve
	mode := context.Mode

	if len(signature) != 2*int(mode) {
		err = errors.New("wrong signature length")
		return
	}

	// r > 0, r < q, s > 0, s < q
	s := gost3410.BytesToBigInt(signature[:mode])
	r := gost3410.BytesToBigInt(signature[mode:])
	if r.Cmp(zero) <= 0 || r.Cmp(curve.Q) >= 0 || s.Cmp(zero) <= 0 || s.Cmp(curve.Q) >= 0 {
		return false, nil
	}

	e := gost3410.СalculateDigest(msg, curve)
	v := big.NewInt(0).ModInverse(e, curve.Q)

	// z1 = s * v mod q
	z1 := big.NewInt(0).Mul(s, v)
	z1.Mod(z1, curve.Q)

	// z2 = -( r * v ) mod q
	z2 := big.NewInt(0).Mul(r, v)
	z2.Sub(curve.Q, z2.Mod(z2, curve.Q))

	// z1 * P
	p1x, p1y, err := curve.Mul(z1, curve.Bx, curve.By)
	if err != nil {
		return false, err
	}

	// z2 * Q
	q1x, q1y, err := curve.Mul(z2, publicKey.X, publicKey.Y)
	if err != nil {
		return false, err
	}

	// C = z1 * P + z2 * Q
	curve.Add(p1x, p1y, q1x, q1y)

	R := big.NewInt(0).Mod(p1x, curve.Q)
	if partialR != nil {
		// R must be equal to partialR
		return R.Cmp(partialR) == 0, nil
	}

	// R must be equal to r
	return R.Cmp(r) == 0, nil
}

func SumPublicKeys(context *gost3410.Context, publicKeys []*gost3410.PublicKey) (sum *gost3410.PublicKey, err error) {
	if publicKeys == nil || len(publicKeys) == 0 {
		err = errors.New("publicKeys is null or empty")
		return
	}

	curve := context.Curve

	x := big.NewInt(0).SetBytes(publicKeys[0].X.Bytes())
	y := big.NewInt(0).SetBytes(publicKeys[0].Y.Bytes())

	for i := 1; i < len(publicKeys); i++ {
		curve.Add(x, y, publicKeys[i].X, publicKeys[i].Y)
	}

	return &gost3410.PublicKey{x, y}, nil
}
