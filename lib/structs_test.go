package libUnLynx_test

import (
	"github.com/lca1/unlynx/lib"
	"github.com/stretchr/testify/assert"
	"gopkg.in/dedis/crypto.v0/abstract"
	"testing"
)

// TestAddClientResponse tests the addition of two client response objects
func TestAddClientResponse(t *testing.T) {
	grouping := []int64{1}
	aggregating := []int64{0, 1, 2, 3, 4}

	sum := []int64{0, 2, 4, 6, 8}

	secKey, pubKey := libUnLynx.GenKey()

	cr1 := libUnLynx.FilteredResponse{GroupByEnc: *libUnLynx.EncryptIntVector(pubKey, grouping), AggregatingAttributes: *libUnLynx.EncryptIntVector(pubKey, aggregating)}
	cr2 := libUnLynx.FilteredResponse{GroupByEnc: *libUnLynx.EncryptIntVector(pubKey, grouping), AggregatingAttributes: *libUnLynx.EncryptIntVector(pubKey, aggregating)}

	newCr := libUnLynx.FilteredResponse{}
	newCr.GroupByEnc = *libUnLynx.EncryptIntVector(pubKey, grouping)
	newCr.AggregatingAttributes = *libUnLynx.NewCipherVector(len(cr1.AggregatingAttributes))
	newCr.Add(cr1, cr2)

	//assert.Equal(t, grouping, lib.UnKey(newCr.GroupingAttributesClear))
	assert.Equal(t, sum, libUnLynx.DecryptIntVector(secKey, &newCr.AggregatingAttributes))
	assert.Equal(t, grouping, libUnLynx.DecryptIntVector(secKey, &newCr.GroupByEnc))
}

// TestCipherVectorTagging tests the CipherVector tag method
func TestCipherVectorTagging(t *testing.T) {
	const N = 1
	groupKey, _, _ := libUnLynx.GenKeys(N)

	target := []int64{1, 2, 3, 4, 5}
	cv := libUnLynx.EncryptIntVector(groupKey, target)

	cl := libUnLynx.ProcessResponse{GroupByEnc: *cv, AggregatingAttributes: *cv}
	es := cl.CipherVectorTag(groupKey)
	_ = es
}

// A function that converts and decrypts a map[string][]byte -> map[string]Ciphertext ->  map[string]int64
func decryptMapBytes(secKey abstract.Scalar, data map[string][]byte) map[string]int64 {
	result := make(map[string]int64)

	for k, v := range data {
		ct := libUnLynx.CipherText{}
		ct.FromBytes(v)

		result[k] = libUnLynx.DecryptInt(secKey, ct)
	}
	return result
}

// TestEncryptDpClearResponse tests the encryption of a DpClearResponse object
func TestEncryptDpClearResponse(t *testing.T) {
	secKey, pubKey := libUnLynx.GenKey()

	groupingClear := libUnLynx.ConvertDataToMap([]int64{2}, "g", 0)
	groupingEnc := libUnLynx.ConvertDataToMap([]int64{1}, "g", len(groupingClear))
	whereClear := libUnLynx.ConvertDataToMap([]int64{}, "w", 0)
	whereEnc := libUnLynx.ConvertDataToMap([]int64{1, 1}, "w", len(whereClear))
	aggrClear := libUnLynx.ConvertDataToMap([]int64{1}, "s", 0)
	aggrEnc := libUnLynx.ConvertDataToMap([]int64{1, 5, 4, 0}, "s", len(aggrClear))

	ccr := libUnLynx.DpClearResponse{
		GroupByClear:               groupingClear,
		GroupByEnc:                 groupingEnc,
		WhereClear:                 whereClear,
		WhereEnc:                   whereEnc,
		AggregatingAttributesClear: aggrClear,
		AggregatingAttributesEnc:   aggrEnc,
	}

	cr := libUnLynx.EncryptDpClearResponse(ccr, pubKey, false)

	assert.Equal(t, ccr.GroupByClear, groupingClear)
	assert.Equal(t, ccr.GroupByEnc, decryptMapBytes(secKey, cr.GroupByEnc))
	assert.Equal(t, ccr.WhereClear, whereClear)
	assert.Equal(t, ccr.WhereEnc, decryptMapBytes(secKey, cr.WhereEnc))
	assert.Equal(t, ccr.AggregatingAttributesClear, aggrClear)
	assert.Equal(t, ccr.AggregatingAttributesEnc, decryptMapBytes(secKey, cr.AggregatingAttributesEnc))
}

// TestFilteredResponseConverter tests the FilteredResponse converter (to bytes). In the meantime we also test the Key and UnKey function ... That is the way to go :D
func TestFilteredResponseConverter(t *testing.T) {
	grouping := []int64{1}
	aggregating := []int64{0, 1, 3, 103, 103}

	secKey, pubKey := libUnLynx.GenKey()

	cr := libUnLynx.FilteredResponse{GroupByEnc: *libUnLynx.EncryptIntVector(pubKey, grouping), AggregatingAttributes: *libUnLynx.EncryptIntVector(pubKey, aggregating)}

	crb, acbLength, aabLength := cr.ToBytes()

	newCr := libUnLynx.FilteredResponse{}
	newCr.FromBytes(crb, aabLength, acbLength)

	assert.Equal(t, aggregating, libUnLynx.DecryptIntVector(secKey, &newCr.AggregatingAttributes))
	assert.Equal(t, grouping, libUnLynx.DecryptIntVector(secKey, &newCr.GroupByEnc))
}

// TestFilteredResponseDetConverter tests the FilteredResponseDet converter (to bytes). In the meantime we also test the Key and UnKey function ... That is the way to go :D
func TestClientResponseDetConverter(t *testing.T) {
	secKey, pubKey := libUnLynx.GenKey()

	grouping := []int64{1}
	aggregating := []int64{0, 1, 3, 103, 103}

	crd := libUnLynx.FilteredResponseDet{DetTagGroupBy: libUnLynx.Key([]int64{1}), Fr: libUnLynx.FilteredResponse{GroupByEnc: *libUnLynx.EncryptIntVector(pubKey, grouping), AggregatingAttributes: *libUnLynx.EncryptIntVector(pubKey, aggregating)}}

	crb, acbLength, aabLength, dtbLength := crd.ToBytes()

	newCrd := libUnLynx.FilteredResponseDet{}
	newCrd.FromBytes(crb, acbLength, aabLength, dtbLength)

	assert.Equal(t, grouping, libUnLynx.UnKey(newCrd.DetTagGroupBy))
	assert.Equal(t, aggregating, libUnLynx.DecryptIntVector(secKey, &newCrd.Fr.AggregatingAttributes))
	assert.Equal(t, grouping, libUnLynx.DecryptIntVector(secKey, &newCrd.Fr.GroupByEnc))
}
