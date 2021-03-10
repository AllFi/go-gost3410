/*
 * Copyright (C) 2019 ING BANK N.V.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package bulletproofs

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/AllFi/go-gost3410"
	"github.com/AllFi/go-gost3410/curve"
	"github.com/AllFi/go-gost3410/hash"
	"github.com/stretchr/testify/assert"
)

func TestXWithinGenericRange(t *testing.T) {
	context := gost3410.NewContext(curve.GOST34102001, hash.GOST34112012256)
	if setupProveVerify18To200(t, context, 40) != true {
		t.Errorf("secret within range should verify successfully")
	}
}

func TestXEqualToRangeStartGeneric(t *testing.T) {
	context := gost3410.NewContext(curve.GOST34102001, hash.GOST34112012256)
	if setupProveVerify18To200(t, context, 18) != true {
		t.Errorf("secret equal to range start should verify successfully")
	}
}

func TestXLessThanRangeStartGeneric(t *testing.T) {
	context := gost3410.NewContext(curve.GOST34102001, hash.GOST34112012256)
	if setupProveVerify18To200(t, context, 17) != false {
		t.Errorf("secret less that range start should fail verification")
	}
}

func TestXGreaterThanRangeEndGeneric(t *testing.T) {
	context := gost3410.NewContext(curve.GOST34102001, hash.GOST34112012256)
	if setupProveVerify18To200(t, context, 201) != false {
		t.Errorf("secret greater than range end should fail verification")
	}
}

func TestXEqualToRangeEndGeneric(t *testing.T) {
	context := gost3410.NewContext(curve.GOST34102001, hash.GOST34112012256)
	if setupProveVerify18To200(t, context, 200) != false {
		t.Errorf("secret equal to range end should fail verification")
	}
}

func setupProveVerify18To200(t *testing.T, context *gost3410.Context, secret int) bool {
	params, errSetup := SetupGeneric(context, 18, 200)
	if errSetup != nil {
		t.Errorf(errSetup.Error())
		t.FailNow()
	}
	bigSecret := new(big.Int).SetInt64(int64(secret))
	proof, errProve := ProveGeneric(context, bigSecret, params)
	if errProve != nil {
		t.Errorf(errProve.Error())
		t.FailNow()
	}
	ok, errVerify := proof.Verify(context)
	if errVerify != nil {
		t.Errorf(errVerify.Error())
		t.FailNow()
	}
	return ok
}

func TestJsonEncodeDecodeBPRP(t *testing.T) {
	// Set up the range, [18, 200) in this case.
	// We want to prove that we are over 18, and less than 200 years old.
	context := gost3410.NewContext(curve.GOST34102001, hash.GOST34112012256)
	params, errSetup := SetupGeneric(context, 18, 200)
	if errSetup != nil {
		t.Errorf(errSetup.Error())
		t.FailNow()
	}

	// Create the proof
	bigSecret := new(big.Int).SetInt64(int64(40))
	proof, errProve := ProveGeneric(context, bigSecret, params)
	if errProve != nil {
		t.Errorf(errProve.Error())
		t.FailNow()
	}

	// Encode the proof to JSON
	jsonEncoded, err := json.Marshal(proof)
	if err != nil {
		t.Fatal("encode error:", err)
	}

	// Here the proof is passed to the verifier, possibly over a network.

	// Decode the proof from JSON
	var decodedProof ProofBPRP
	err = json.Unmarshal(jsonEncoded, &decodedProof)
	if err != nil {
		t.Fatal("decode error:", err)
	}

	assert.Equal(t, proof, decodedProof, "should be equal")

	// Verify the proof
	ok, errVerify := decodedProof.Verify(context)
	if errVerify != nil {
		t.Errorf(errVerify.Error())
		t.FailNow()
	}
	assert.True(t, ok, "should verify")
}
