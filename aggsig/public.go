package aggsig

import (
	"github.com/AllFi/go-gost3410"
	"github.com/AllFi/go-gost3410/curve"
	"github.com/pkg/errors"
)

type PublicKey struct {
	curve.Point
}

func NewPublicKey(context *gost3410.Context, rawPrivateKey []byte) (publicKey *PublicKey, err error) {
	privateKey, err := NewPrivateKey(context, rawPrivateKey)
	if err != nil {
		err = errors.Wrap(err, "cannot NewPrivateKey")
		return
	}

	return privateKey.PublicKey(context)
}
