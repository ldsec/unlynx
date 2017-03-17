package lib_test

import (
	"testing"

	"github.com/JoaoAndreSa/MedCo/lib"
	"github.com/stretchr/testify/assert"
)

// TestAddClientResponse tests the addition of two client response objects
func TestAddClientResponse(t *testing.T) {
	grouping := []int64{1}
	aggregating := []int64{0, 1, 2, 3, 4}

	sum := []int64{0, 2, 4, 6, 8}

	secKey, pubKey := lib.GenKey()

	cr1 := lib.FilteredResponse{*lib.EncryptIntVector(pubKey, grouping), *lib.EncryptIntVector(pubKey, aggregating)}
	cr2 := lib.FilteredResponse{*lib.EncryptIntVector(pubKey, grouping), *lib.EncryptIntVector(pubKey, aggregating)}

	newCr := lib.FilteredResponse{}
	newCr.GroupByEnc = *lib.EncryptIntVector(pubKey, grouping)
	newCr.AggregatingAttributes = *lib.NewCipherVector(len(cr1.AggregatingAttributes))
	newCr.Add(cr1, cr2)

	//assert.Equal(t, grouping, lib.UnKey(newCr.GroupingAttributesClear))
	assert.Equal(t, sum, lib.DecryptIntVector(secKey, &newCr.AggregatingAttributes))
	assert.Equal(t, grouping, lib.DecryptIntVector(secKey, &newCr.GroupByEnc))
}

// TestCipherVectorTagging tests the ciphervector tag method
func TestCipherVectorTagging(t *testing.T) {
	const N = 1
	groupKey, _, _ := lib.GenKeys(N)

	target := []int64{1, 2, 3, 4, 5}
	cv := lib.EncryptIntVector(groupKey, target)

	cl := lib.ProcessResponse{GroupByEnc: *cv, AggregatingAttributes: *cv}
	es := cl.CipherVectorTag(groupKey)
	_ = es
}

// EncryptDpClearResponse test the encryption of a DpClearResponse object
func TestEncryptDpClearResponse(t *testing.T) {
	/*secKey, pubKey := lib.GenKey()

	groupingClear := []int64{2}
	grouping := []int64{1}
	aggregating := []int64{0, 1, 2, 3, 4}

	ccr := lib.DpClearResponse{[]int64{1}, []int64{1}, groupingClear, grouping, aggregating}

	cr := lib.EncryptDpClearResponse(ccr, pubKey)

	//assert.Equal(t, groupingClear, lib.UnKey(cr.GroupingAttributesClear))
	assert.Equal(t, ccr.GroupByClear, groupingClear)
	assert.Equal(t, ccr.WhereClear, []int64{1})
	assert.Equal(t, aggregating, lib.DecryptIntVector(secKey, &cr.AggregatingAttributes))
	assert.Equal(t, grouping, lib.DecryptIntVector(secKey, &cr.GroupByEnc))
	assert.Equal(t, []int64{1}, lib.DecryptIntVector(secKey, &cr.WhereEnc))*/
}

// TestFilteredResponseConverter tests the FilteredResponse converter (to bytes). In the meantime we also test the Key and UnKey function ... That is the way to go :D
func TestFilteredResponseConverter(t *testing.T) {
	grouping := []int64{1}
	aggregating := []int64{0, 1, 3, 103, 103}

	secKey, pubKey := lib.GenKey()

	cr := lib.FilteredResponse{GroupByEnc:*lib.EncryptIntVector(pubKey, grouping), AggregatingAttributes: *lib.EncryptIntVector(pubKey, aggregating)}

	crb, acbLength, aabLength := cr.ToBytes()

	newCr := lib.FilteredResponse{}
	newCr.FromBytes(crb, aabLength, acbLength)

	assert.Equal(t, aggregating, lib.DecryptIntVector(secKey, &newCr.AggregatingAttributes))
	assert.Equal(t, grouping, lib.DecryptIntVector(secKey, &newCr.GroupByEnc))
}

// TestFilteredResponseDetConverter tests the FilteredResponseDet converter (to bytes). In the meantime we also test the Key and UnKey function ... That is the way to go :D
func TestClientResponseDetConverter(t *testing.T) {
	secKey, pubKey := lib.GenKey()

	grouping := []int64{1}
	aggregating := []int64{0, 1, 3, 103, 103}

	crd := lib.FilteredResponseDet{DetTagGroupBy: lib.Key([]int64{1}), Fr: lib.FilteredResponse{GroupByEnc: *lib.EncryptIntVector(pubKey, grouping), AggregatingAttributes: *lib.EncryptIntVector(pubKey, aggregating)}}

	crb, acbLength, aabLength, dtbLength := crd.ToBytes()

	newCrd := lib.FilteredResponseDet{}
	newCrd.FromBytes(crb, acbLength, aabLength, dtbLength)

	assert.Equal(t, grouping, lib.UnKey(newCrd.DetTagGroupBy))
	assert.Equal(t, aggregating, lib.DecryptIntVector(secKey, &newCrd.Fr.AggregatingAttributes))
	assert.Equal(t, grouping, lib.DecryptIntVector(secKey, &newCrd.Fr.GroupByEnc))
}
