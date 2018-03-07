package encoding

import (
	"github.com/dedis/kyber"
	"github.com/lca1/unlynx/lib"
)

// EncodeSum computes the sum of query results
func EncodeSum(input []int64, pubKey kyber.Point) *libunlynx.CipherText {
	//sum the local DP's query results
	sum := int64(0)
	for _, el := range input {
		sum = sum + el
	}

	//encrypt the local DP's query result
	sumEncrypted := libunlynx.EncryptInt(pubKey, sum)

	//input range validation proof
	// IS TODO FOR ALL OPERATIONS FOR NOW

	return sumEncrypted
}

// DecodeSum computes the sum of local DP's query results
func DecodeSum(result libunlynx.CipherText, secKey kyber.Scalar) int64 {
	//decrypt the query results
	return libunlynx.DecryptInt(secKey, result)

}
