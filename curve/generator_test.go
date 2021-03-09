package curve

import (
	"fmt"
	"testing"

	"github.com/AllFi/go-gost3410/utils"

	"github.com/stretchr/testify/assert"
)

func TestNewGenerator(t *testing.T) {
	curve := GOST34102001()
	mode := curve.Params().BitSize / 8
	seed := utils.RandomBytes(mode)
	generator, err := NewGenerator(curve, seed)
	assert.NoError(t, err)
	fmt.Println(generator)
}
