package bulletproofs

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/AllFi/go-gost3410"
	"github.com/AllFi/go-gost3410/curve"
	"github.com/AllFi/go-gost3410/hash"
	"github.com/stretchr/testify/assert"
)

func TestMultiparty(t *testing.T) {
	context := gost3410.NewContext(curve.GOST34102001, hash.GOST34112012256)
	order := context.Curve.Params().N
	params, errSetup := Setup(context, MAX_RANGE_END)
	assert.NoError(t, errSetup)

	dealerValue := new(big.Int).SetInt64(int64(300))
	dealerBlind, _ := rand.Int(rand.Reader, order)

	participantsCount := 2
	participantsBlinds := make([]*big.Int, 0)
	for i := 0; i < participantsCount; i++ {
		blind, _ := rand.Int(rand.Reader, order)
		participantsBlinds = append(participantsBlinds, blind)
	}

	participantsContexts := make([]*MPCPContext, 0)
	publicTau1s := make([]*curve.Point, 0)
	publicTau2s := make([]*curve.Point, 0)
	for _ = range participantsBlinds {
		context, publicTau1, publicTau2 := PartialPreProve(context, params)
		publicTau1s = append(publicTau1s, publicTau1)
		publicTau2s = append(publicTau2s, publicTau2)
		participantsContexts = append(participantsContexts, context)
	}

	dealerContext, dealerPublicTau1, dealerPublicTau2 := PartialPreProve(context, params)
	publicTau1s = append(publicTau1s, dealerPublicTau1)
	publicTau2s = append(publicTau2s, dealerPublicTau2)

	tauxs := make([]*big.Int, 0)
	for i := 0; i < len(participantsContexts); i++ {
		_, taux, err := PartialProve(context, big.NewInt(0), participantsBlinds[i], participantsContexts[i], publicTau1s, publicTau2s, params)
		assert.NoError(t, err)
		tauxs = append(tauxs, taux)
	}

	dealerContext, dealerTaux, err := PartialProve(context, dealerValue, dealerBlind, dealerContext, publicTau1s, publicTau2s, params)
	assert.NoError(t, err)

	tauxs = append(tauxs, dealerTaux)
	_, err = AggregateProofs(dealerContext, tauxs, params)
	assert.NoError(t, err)
}
