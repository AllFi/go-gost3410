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
	"crypto/elliptic"
	"encoding/json"
	"math"
	"math/big"
	"testing"

	"github.com/AllFi/go-gost3410/curve"

	"github.com/stretchr/testify/assert"
)

func TestXEqualsRangeStart(t *testing.T) {
	rangeEnd := int64(math.Pow(2, 32))
	x := new(big.Int).SetInt64(0)
	ec := curve.GOST34102001()

	params := setupRange(t, ec, rangeEnd)
	if proveAndVerifyRange(ec, x, params) != true {
		t.Errorf("x equal to range start should verify successfully")
	}
}

func TestXLowerThanRangeStart(t *testing.T) {
	rangeEnd := int64(math.Pow(2, 32))
	x := new(big.Int).SetInt64(-1)
	ec := curve.GOST34102001()

	params := setupRange(t, ec, rangeEnd)
	if proveAndVerifyRange(ec, x, params) == true {
		t.Errorf("x lower than range start should not verify")
	}
}

func TestXHigherThanRangeEnd(t *testing.T) {
	rangeEnd := int64(math.Pow(2, 32))
	x := new(big.Int).SetInt64(rangeEnd + 1)
	ec := curve.GOST34102001()

	params := setupRange(t, ec, rangeEnd)
	if proveAndVerifyRange(ec, x, params) == true {
		t.Errorf("x higher than range end should not verify")
	}
}

func TestXEqualToRangeEnd(t *testing.T) {
	rangeEnd := int64(math.Pow(2, 32))
	x := new(big.Int).SetInt64(rangeEnd)
	ec := curve.GOST34102001()

	params := setupRange(t, ec, rangeEnd)
	if proveAndVerifyRange(ec, x, params) == true {
		t.Errorf("x equal to range end should not verify")
	}
}

func TestXWithinRange(t *testing.T) {
	rangeEnd := int64(math.Pow(2, 32))
	x := new(big.Int).SetInt64(3)
	ec := curve.GOST34102001()

	params := setupRange(t, ec, rangeEnd)
	if proveAndVerifyRange(ec, x, params) != true {
		t.Errorf("x within range should verify successfully")
	}
}

func setupRange(t *testing.T, ec elliptic.Curve, rangeEnd int64) BulletProofSetupParams {
	params, err := Setup(ec, rangeEnd)
	if err != nil {
		t.Errorf("Invalid range end: %s", err)
		t.FailNow()
	}
	return params
}

func proveAndVerifyRange(ec elliptic.Curve, x *big.Int, params BulletProofSetupParams) bool {
	proof, _ := Prove(ec, x, params)
	ok, _ := proof.Verify(ec)
	return ok
}

func TestJsonEncodeDecode(t *testing.T) {
	ec := curve.GOST34102001()
	params, _ := Setup(ec, MAX_RANGE_END)
	proof, _ := Prove(ec, new(big.Int).SetInt64(18), params)
	jsonEncoded, err := json.Marshal(proof)
	if err != nil {
		t.Fatal("encode error:", err)
	}

	// network transfer takes place here

	var decodedProof BulletProof
	err = json.Unmarshal(jsonEncoded, &decodedProof)
	if err != nil {
		t.Fatal("decode error:", err)
	}

	assert.Equal(t, proof, decodedProof, "should be equal")

	ok, err := decodedProof.Verify(ec)
	if err != nil {
		t.Fatal("verify error:", err)
	}
	assert.True(t, ok, "should verify")
}
