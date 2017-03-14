package lib_test

import (
	"testing"

	"github.com/JoaoAndreSa/MedCo/lib"
	"github.com/stretchr/testify/assert"
	"gopkg.in/dedis/crypto.v0/abstract"
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

// EncryptClientClearResponse test the encryption of a ClientClearResponse object
func TestEncryptClientClearResponse(t *testing.T) {
	secKey, pubKey := lib.GenKey()

	groupingClear := []int64{2}
	grouping := []int64{1}
	aggregating := []int64{0, 1, 2, 3, 4}

	ccr := lib.DpClearResponse{[]int64{1}, []int64{1}, []int64{1}, []int64{1}, []int64{5}}

	ccr.GroupByClear = groupingClear
	ccr.AggregatingAttributes = aggregating
	ccr.GroupByEnc = grouping

	cr := lib.EncryptClientClearResponse(ccr, pubKey)

	//assert.Equal(t, groupingClear, lib.UnKey(cr.GroupingAttributesClear))
	assert.Equal(t, aggregating, lib.DecryptIntVector(secKey, &cr.AggregatingAttributes))
	assert.Equal(t, grouping, lib.DecryptIntVector(secKey, &cr.GroupByEnc))
}

// TestClientResponseConverter tests the ClientResponse converter (to bytes). In the meantime we also test the Key and UnKey function ... That is the way to go :D
func TestClientResponseConverter(t *testing.T) {
	grouping := []int64{1}
	aggregating := []int64{0, 1, 3, 103, 103}

	secKey, pubKey := lib.GenKey()

	cr := newClientResponse(pubKey, grouping, aggregating)

	crb, acbLength, aabLength, pgaebLength := cr.ToBytes()

	newCr := lib.ClientResponse{}
	newCr.FromBytes(crb, acbLength, aabLength, pgaebLength)

	assert.Equal(t, grouping, lib.UnKey(newCr.GroupingAttributesClear))
	assert.Equal(t, aggregating, lib.DecryptIntVector(secKey, &newCr.AggregatingAttributes))
	assert.Equal(t, grouping, lib.DecryptIntVector(secKey, &newCr.ProbaGroupingAttributesEnc))
}

// TestClientResponseDetConverter tests the ClientResponseDet converter (to bytes). In the meantime we also test the Key and UnKey function ... That is the way to go :D
func TestClientResponseDetConverter(t *testing.T) {
	secKey, pubKey := lib.GenKey()

	grouping := []int64{1}
	aggregating := []int64{0, 1, 3, 103, 103}

	crd := lib.FilteredResponseDet{DetTagGroupBy: lib.Key([]int64{1}), Fr: lib.FilteredResponse{GroupByEnc: *lib.EncryptIntVector(pubKey, grouping), AggregatingAttributes: *lib.EncryptIntVector(pubKey, aggregating)}}

	crb, acbLength, aabLength, dtbLength := crd.ToBytes()

	newCrd := lib.FilteredResponseDet{}
	newCrd.FromBytes(crb, acbLength, aabLength, dtbLength)

	assert.Equal(t, grouping, lib.UnKey(newCrd.DetTagGroupBy))
	//assert.Equal(t, grouping, lib.UnKey(newCrd.Fr.))
	assert.Equal(t, aggregating, lib.DecryptIntVector(secKey, &newCrd.Fr.AggregatingAttributes))
	assert.Equal(t, grouping, lib.DecryptIntVector(secKey, &newCrd.Fr.GroupByEnc))
}

// newClientResponse creates a new ClientResponse object with actual data
func newClientResponse(pubKey abstract.Point, grouping, aggregating []int64) lib.ClientResponse {
	cr := lib.ClientResponse{}
	cr.GroupingAttributesClear = lib.Key(grouping)
	cr.AggregatingAttributes = *lib.EncryptIntVector(pubKey, aggregating)
	cr.ProbaGroupingAttributesEnc = *lib.EncryptIntVector(pubKey, grouping)

	return cr
}

// newClientResponseDet creates a new ClientResponseDet object with actual data
func newClientResponseDet(pubKey abstract.Point, grouping, aggregating []int64) lib.FilteredResponseDet {
	cr := lib.FilteredResponseDet{}
	cr.Fr = lib.FilteredResponse{*lib.EncryptIntVector(pubKey, grouping), *lib.EncryptIntVector(pubKey, aggregating)}
	cr.DetTagGroupBy = lib.Key(grouping)

	return cr
}
