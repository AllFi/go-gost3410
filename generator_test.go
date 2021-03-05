package gost3410

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenerator(t *testing.T) {
	mode := Mode2001
	curveParams := CurveParamsGostR34102001CryptoProA
	context, err := NewContext(mode, curveParams)
	assert.NoError(t, err)

	seed := randomBytes(int(mode), context)
	generator, err := NewGenerator(context, seed)
	assert.NoError(t, err)
	fmt.Println(generator)
}
