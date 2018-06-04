package libunlynx_test

import (
	"github.com/dedis/kyber"
	"github.com/lca1/unlynx/lib"
	"github.com/stretchr/testify/assert"
	"strconv"
	"testing"
)

// TestAddClientResponse tests the addition of two client response objects
func TestAddClientResponse(t *testing.T) {
	grouping := []int64{1}
	aggregating := []int64{0, 1, 2, 3, 4}

	sum := []int64{0, 2, 4, 6, 8}

	secKey, pubKey := libunlynx.GenKey()

	cr1 := libunlynx.FilteredResponse{GroupByEnc: *libunlynx.EncryptIntVector(pubKey, grouping), AggregatingAttributes: *libunlynx.EncryptIntVector(pubKey, aggregating)}
	cr2 := libunlynx.FilteredResponse{GroupByEnc: *libunlynx.EncryptIntVector(pubKey, grouping), AggregatingAttributes: *libunlynx.EncryptIntVector(pubKey, aggregating)}

	newCr := libunlynx.FilteredResponse{}
	newCr.GroupByEnc = *libunlynx.EncryptIntVector(pubKey, grouping)
	newCr.AggregatingAttributes = *libunlynx.NewCipherVector(len(cr1.AggregatingAttributes))
	newCr.Add(cr1, cr2)

	//assert.Equal(t, grouping, lib.UnKey(newCr.GroupingAttributesClear))
	assert.Equal(t, sum, libunlynx.DecryptIntVector(secKey, &newCr.AggregatingAttributes))
	assert.Equal(t, grouping, libunlynx.DecryptIntVector(secKey, &newCr.GroupByEnc))
}

// TestCipherVectorTagging tests the CipherVector tag method
func TestCipherVectorTagging(t *testing.T) {
	const N = 1
	groupKey, _, _ := libunlynx.GenKeys(N)

	target := []int64{1, 2, 3, 4, 5}
	cv := libunlynx.EncryptIntVector(groupKey, target)

	es := cv.CipherVectorTag(groupKey)
	_ = es
}

// A function that converts and decrypts a map[string][]byte -> map[string]Ciphertext ->  map[string]int64
func decryptMapBytes(secKey kyber.Scalar, data map[string][]byte) map[string]int64 {
	result := make(map[string]int64)

	for k, v := range data {
		ct := libunlynx.CipherText{}
		ct.FromBytes(v)

		result[k] = libunlynx.DecryptInt(secKey, ct)
	}
	return result
}

// TestEncryptDpClearResponse tests the encryption of a DpClearResponse object
func TestEncryptDpClearResponse(t *testing.T) {
	secKey, pubKey := libunlynx.GenKey()

	groupingClear := libunlynx.ConvertDataToMap([]int64{2}, "g", 0)
	groupingEnc := libunlynx.ConvertDataToMap([]int64{1}, "g", len(groupingClear))
	whereClear := libunlynx.ConvertDataToMap([]int64{}, "w", 0)
	whereEnc := libunlynx.ConvertDataToMap([]int64{1, 1}, "w", len(whereClear))
	aggrClear := libunlynx.ConvertDataToMap([]int64{1}, "s", 0)
	aggrEnc := libunlynx.ConvertDataToMap([]int64{1, 5, 4, 0}, "s", len(aggrClear))

	ccr := libunlynx.DpClearResponse{
		GroupByClear:               groupingClear,
		GroupByEnc:                 groupingEnc,
		WhereClear:                 whereClear,
		WhereEnc:                   whereEnc,
		AggregatingAttributesClear: aggrClear,
		AggregatingAttributesEnc:   aggrEnc,
	}

	cr := libunlynx.EncryptDpClearResponse(ccr, pubKey, false)

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

	secKey, pubKey := libunlynx.GenKey()

	cr := libunlynx.FilteredResponse{GroupByEnc: *libunlynx.EncryptIntVector(pubKey, grouping), AggregatingAttributes: *libunlynx.EncryptIntVector(pubKey, aggregating)}

	crb, acbLength, aabLength := cr.ToBytes()

	newCr := libunlynx.FilteredResponse{}
	newCr.FromBytes(crb, aabLength, acbLength)

	assert.Equal(t, aggregating, libunlynx.DecryptIntVector(secKey, &newCr.AggregatingAttributes))
	assert.Equal(t, grouping, libunlynx.DecryptIntVector(secKey, &newCr.GroupByEnc))
}

// TestFilteredResponseDetConverter tests the FilteredResponseDet converter (to bytes). In the meantime we also test the Key and UnKey function ... That is the way to go :D
func TestClientResponseDetConverter(t *testing.T) {
	secKey, pubKey := libunlynx.GenKey()

	grouping := []int64{1}
	aggregating := []int64{0, 1, 3, 103, 103}

	crd := libunlynx.FilteredResponseDet{DetTagGroupBy: libunlynx.Key([]int64{1}), Fr: libunlynx.FilteredResponse{GroupByEnc: *libunlynx.EncryptIntVector(pubKey, grouping), AggregatingAttributes: *libunlynx.EncryptIntVector(pubKey, aggregating)}}

	crb, acbLength, aabLength, dtbLength := crd.ToBytes()

	newCrd := libunlynx.FilteredResponseDet{}
	newCrd.FromBytes(crb, acbLength, aabLength, dtbLength)

	assert.Equal(t, grouping, libunlynx.UnKey(newCrd.DetTagGroupBy))
	assert.Equal(t, aggregating, libunlynx.DecryptIntVector(secKey, &newCrd.Fr.AggregatingAttributes))
	assert.Equal(t, grouping, libunlynx.DecryptIntVector(secKey, &newCrd.Fr.GroupByEnc))
}

// TestProcessResponseConverter tests the ProcessResponse converter (to bytes).
func TestProcessResponseConverter(t *testing.T) {
	whereEnc := []int64{1, 5, 6}
	grouping := []int64{1}
	aggregating := []int64{0, 1, 3, 103, 103}

	secKey, pubKey := libunlynx.GenKey()

	pr := libunlynx.ProcessResponse{
		WhereEnc:              *libunlynx.EncryptIntVector(pubKey, whereEnc),
		GroupByEnc:            *libunlynx.EncryptIntVector(pubKey, grouping),
		AggregatingAttributes: *libunlynx.EncryptIntVector(pubKey, aggregating),
	}

	b, gacbLength, aabLength, pgaebLength := pr.ToBytes()
	newPr := libunlynx.ProcessResponse{}
	newPr.FromBytes(b, gacbLength, aabLength, pgaebLength)

	assert.Equal(t, whereEnc, libunlynx.DecryptIntVector(secKey, &newPr.WhereEnc))
	assert.Equal(t, grouping, libunlynx.DecryptIntVector(secKey, &newPr.GroupByEnc))
	assert.Equal(t, aggregating, libunlynx.DecryptIntVector(secKey, &newPr.AggregatingAttributes))
}

func TestProcessResponseDetConverter(t *testing.T) {
	whereEnc := []int64{1, 5, 6}
	grouping := []int64{1}
	aggregating := []int64{0, 1, 3, 103, 103}

	_, pubKey := libunlynx.GenKey()

	pr := libunlynx.ProcessResponse{
		WhereEnc:              *libunlynx.EncryptIntVector(pubKey, whereEnc),
		GroupByEnc:            *libunlynx.EncryptIntVector(pubKey, grouping),
		AggregatingAttributes: *libunlynx.EncryptIntVector(pubKey, aggregating),
	}

	detTagWhere := make([]libunlynx.GroupingKey, 2)
	detTagWhere[0] = libunlynx.GroupingKey("test1")
	detTagWhere[1] = libunlynx.GroupingKey("test2")
	prDet := libunlynx.ProcessResponseDet{
		PR:            pr,
		DetTagGroupBy: "",
		DetTagWhere:   detTagWhere,
	}

	b, gacbLength, aabLength, pgaebLength, dtbgbLength, dtbwLength := prDet.ToBytes()
	newPrDet := libunlynx.ProcessResponseDet{
		PR:            libunlynx.ProcessResponse{},
		DetTagGroupBy: "",
		DetTagWhere:   nil,
	}
	newPrDet.FromBytes(b, gacbLength, aabLength, pgaebLength, dtbgbLength, dtbwLength)

	assert.Equal(t, prDet.DetTagGroupBy, newPrDet.DetTagGroupBy)
	assert.Equal(t, prDet.DetTagWhere, newPrDet.DetTagWhere)
	// We already tested the ProcessResponseConverter, no need to redo it
}

func TestDPResponseConverter(t *testing.T) {
	k := 5
	secKey, pubKey := libunlynx.GenKey()
	dpResponseToSend := libunlynx.DpResponseToSend{
		WhereClear:                 make(map[string]int64),
		WhereEnc:                   make(map[string][]byte),
		GroupByClear:               make(map[string]int64),
		GroupByEnc:                 make(map[string][]byte),
		AggregatingAttributesClear: make(map[string]int64),
		AggregatingAttributesEnc:   make(map[string][]byte),
	}
	for i := 0; i < k; i++ {
		dpResponseToSend.GroupByClear[strconv.Itoa(i)] = int64(i)
		dpResponseToSend.WhereClear[strconv.Itoa(i)] = int64(i)
		dpResponseToSend.AggregatingAttributesClear[strconv.Itoa(i)] = int64(i)
		dpResponseToSend.GroupByEnc[strconv.Itoa(i)] = libunlynx.EncryptInt(pubKey, int64(i)).ToBytes()
		dpResponseToSend.WhereEnc[strconv.Itoa(i)] = libunlynx.EncryptInt(pubKey, int64(i)).ToBytes()
		dpResponseToSend.AggregatingAttributesEnc[strconv.Itoa(i)] = libunlynx.EncryptInt(pubKey, int64(i)).ToBytes()
	}

	dpResponse := libunlynx.DpResponse{
		WhereClear:                 nil,
		WhereEnc:                   nil,
		GroupByClear:               nil,
		GroupByEnc:                 nil,
		AggregatingAttributesClear: nil,
		AggregatingAttributesEnc:   nil,
	}

	dpResponse.FromDpResponseToSend(dpResponseToSend)

	for i := 0; i < k; i++ {
		assert.Equal(t, libunlynx.DecryptInt(secKey, dpResponse.GroupByEnc[strconv.Itoa(i)]), int64(i))
		assert.Equal(t, libunlynx.DecryptInt(secKey, dpResponse.WhereEnc[strconv.Itoa(i)]), int64(i))
		assert.Equal(t, libunlynx.DecryptInt(secKey, dpResponse.AggregatingAttributesEnc[strconv.Itoa(i)]), int64(i))
		assert.Equal(t, dpResponse.GroupByClear[strconv.Itoa(i)], int64(i))
		assert.Equal(t, dpResponse.WhereClear[strconv.Itoa(i)], int64(i))
		assert.Equal(t, dpResponse.AggregatingAttributesClear[strconv.Itoa(i)], int64(i))
	}
}

func TestFromDpClearResponseToProcess(t *testing.T) {
	k := 5
	secKey, pubKey := libunlynx.GenKey()
	dpClearResponse := libunlynx.DpClearResponse{
		WhereClear:                 make(map[string]int64),
		WhereEnc:                   make(map[string]int64),
		GroupByClear:               make(map[string]int64),
		GroupByEnc:                 make(map[string]int64),
		AggregatingAttributesClear: make(map[string]int64),
		AggregatingAttributesEnc:   make(map[string]int64),
	}

	for i := 0; i < k; i++ {
		dpClearResponse.GroupByClear["g"+strconv.Itoa(i)] = int64(i)
		dpClearResponse.GroupByEnc["g"+strconv.Itoa(i+k)] = int64(i)
		dpClearResponse.WhereClear["w"+strconv.Itoa(i)] = int64(i)
		dpClearResponse.WhereEnc["w"+strconv.Itoa(i+k)] = int64(i)
		dpClearResponse.AggregatingAttributesClear["s"+strconv.Itoa(i)] = int64(i)
		dpClearResponse.AggregatingAttributesEnc["s"+strconv.Itoa(i+k)] = int64(i)
	}

	pr := dpClearResponse.FromDpClearResponseToProcess(pubKey)

	for i := 0; i < k; i++ {
		pos := i
		v := dpClearResponse.GroupByClear["g"+strconv.Itoa(i)]
		assert.Equal(t, libunlynx.DecryptInt(secKey, pr.GroupByEnc[pos]), v)
		pos += len(dpClearResponse.GroupByClear)
		v = dpClearResponse.GroupByEnc["g"+strconv.Itoa(i+k)]
		assert.Equal(t, libunlynx.DecryptInt(secKey, pr.GroupByEnc[pos]), v)

		pos = i
		v = dpClearResponse.WhereClear["w"+strconv.Itoa(i)]
		assert.Equal(t, libunlynx.DecryptInt(secKey, pr.WhereEnc[pos]), v)
		pos += len(dpClearResponse.WhereClear)
		v = dpClearResponse.WhereEnc["w"+strconv.Itoa(i+k)]
		assert.Equal(t, libunlynx.DecryptInt(secKey, pr.WhereEnc[pos]), v)

		pos = i
		v = dpClearResponse.AggregatingAttributesClear["s"+strconv.Itoa(i)]
		assert.Equal(t, libunlynx.DecryptInt(secKey, pr.AggregatingAttributes[pos]), v)
		pos += len(dpClearResponse.AggregatingAttributesClear)
		v = dpClearResponse.AggregatingAttributesEnc["s"+strconv.Itoa(i+k)]
		assert.Equal(t, libunlynx.DecryptInt(secKey, pr.AggregatingAttributes[pos]), v)
	}
}

func TestMapBytesToMapCipherText(t *testing.T) {
	k := 5
	secKey, pubKey := libunlynx.GenKey()

	bMap := make(map[string][]byte)
	for i := 0; i < k; i++ {
		bMap[strconv.Itoa(i)] = libunlynx.EncryptInt(pubKey, int64(i)).ToBytes()
	}
	ctMap := libunlynx.MapBytesToMapCipherText(bMap)
	for i := 0; i < k; i++ {
		assert.Equal(t, libunlynx.DecryptInt(secKey, ctMap[strconv.Itoa(i)]), int64(i))
	}
}
