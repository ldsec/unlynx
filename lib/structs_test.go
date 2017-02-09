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

	cr1 := newClientResponse(pubKey, grouping, aggregating)
	cr2 := newClientResponse(pubKey, grouping, aggregating)

	newCr := lib.NewClientResponse(1, 5)
	newCr.GroupingAttributesClear = lib.Key(grouping)
	newCr.Add(cr1, cr2)

	assert.Equal(t, grouping, lib.UnKey(newCr.GroupingAttributesClear))
	assert.Equal(t, sum, lib.DecryptIntVector(secKey, &newCr.AggregatingAttributes))
	assert.Equal(t, grouping, lib.DecryptIntVector(secKey, &newCr.ProbaGroupingAttributesEnc))
}

// TestCipherVectorTagging tests the ciphervector tag method
func TestCipherVectorTagging(t *testing.T) {
	const N = 1
	groupKey, _, _ := lib.GenKeys(N)

	target := []int64{1, 2, 3, 4, 5}
	cv := lib.EncryptIntVector(groupKey, target)
	cl := lib.ClientResponse{"", *cv, *cv}
	es := cl.CipherVectorTag(groupKey)
	_ = es
}

// EncryptClientClearResponse test the encryption of a ClientClearResponse object
func TestEncryptClientClearResponse(t *testing.T) {
	secKey, pubKey := lib.GenKey()

	groupingClear := []int64{2}
	grouping := []int64{1}
	aggregating := []int64{0, 1, 2, 3, 4}

	ccr := lib.NewClientClearResponse(1, 1, 5)

	ccr.GroupingAttributesClear = groupingClear
	ccr.AggregatingAttributes = aggregating
	ccr.GroupingAttributesEnc = grouping

	cr := lib.EncryptClientClearResponse(ccr, pubKey)

	assert.Equal(t, groupingClear, lib.UnKey(cr.GroupingAttributesClear))
	assert.Equal(t, aggregating, lib.DecryptIntVector(secKey, &cr.AggregatingAttributes))
	assert.Equal(t, grouping, lib.DecryptIntVector(secKey, &cr.ProbaGroupingAttributesEnc))
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

	crd := newClientResponseDet(pubKey, grouping, aggregating)

	crb, acbLength, aabLength, pgaebLength, dtbLength := crd.ToBytes()

	newCrd := lib.ClientResponseDet{}
	newCrd.FromBytes(crb, acbLength, aabLength, pgaebLength, dtbLength)

	assert.Equal(t, grouping, lib.UnKey(newCrd.DetTag))
	assert.Equal(t, grouping, lib.UnKey(newCrd.CR.GroupingAttributesClear))
	assert.Equal(t, aggregating, lib.DecryptIntVector(secKey, &newCrd.CR.AggregatingAttributes))
	assert.Equal(t, grouping, lib.DecryptIntVector(secKey, &newCrd.CR.ProbaGroupingAttributesEnc))
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
func newClientResponseDet(pubKey abstract.Point, grouping, aggregating []int64) lib.ClientResponseDet {
	cr := lib.ClientResponseDet{}
	cr.CR = newClientResponse(pubKey, grouping, aggregating)
	cr.DetTag = lib.Key(grouping)

	return cr
}
