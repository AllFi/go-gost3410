package gost3410

import (
	"github.com/pkg/errors"
)

type Context struct {
	Mode  Mode
	Curve *Curve
}

func NewContext(mode Mode, curveParams CurveParams) (context *Context, err error) {
	curve, err := NewCurveFromParams(curveParams)
	if err != nil {
		err = errors.Wrap(err, "cannot NewCurveFromParams")
		return
	}
	return &Context{Mode: mode, Curve: curve}, nil
}
