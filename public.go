package gost3410

import (
	"math/big"

	"github.com/pkg/errors"
)

type PublicKey struct {
	X *big.Int
	Y *big.Int
}

func NewPublicKey(context *Context, rawPrivateKey []byte) (publicKey *PublicKey, err error) {
	privateKey, err := NewPrivateKey(context, rawPrivateKey)
	if err != nil {
		err = errors.Wrap(err, "cannot NewPrivateKey")
		return
	}

	return privateKey.PublicKey(context)
}

func (pub *PublicKey) Raw(context *Context) []byte {
	raw := append(
		Pad(pub.Y.Bytes(), int(context.Mode)),
		Pad(pub.X.Bytes(), int(context.Mode))...,
	)
	reverse(raw)
	return raw
}
