package encoding

import (
	"github.com/lca1/unlynx/lib"
	"github.com/stretchr/testify/assert"
	"testing"
)

// TestEncodeDecodeSum tests EncodeSum and DecodeSum
func TestEncodeDecodeSum(t *testing.T) {
	//data
	inputValues := []int64{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	// key
	secKey, pubKey := libunlynx.GenKey()
	//expected results
	expect := int64(0)
	for _, el := range inputValues {
		expect = expect + el
	}

	//function call
	resultEncrypted := EncodeSum(inputValues, pubKey)

	result := DecodeSum(*resultEncrypted, secKey)

	assert.Equal(t, expect, result)

}
