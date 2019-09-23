package protocolsunlynx_test

import (
	"reflect"
	"testing"

	"github.com/ldsec/unlynx/lib"
	"github.com/ldsec/unlynx/protocols"
	"github.com/stretchr/testify/assert"
)

// Create test for the further tools used in protocols and services to ensure shortly if a modification change the behaviour

func TestRetrieveSimpleDataFromMap(t *testing.T) {
	secKey, pubKey := libunlynx.GenKey()

	k := 5
	mapToTest := make(map[libunlynx.GroupingKey]libunlynx.FilteredResponse)
	mapToTest[protocolsunlynx.EMPTYKEY] = libunlynx.FilteredResponse{
		AggregatingAttributes: make(libunlynx.CipherVector, k),
	}
	for i := 0; i < k; i++ {
		mapToTest[protocolsunlynx.EMPTYKEY].AggregatingAttributes[i] = *libunlynx.EncryptInt(pubKey, int64(i))
	}

	result, err := protocolsunlynx.RetrieveSimpleDataFromMap(mapToTest)
	assert.Nil(t, err)
	for i, v := range result {
		assert.Equal(t, int64(i), libunlynx.DecryptInt(secKey, v))
	}
}

func TestProcessResponseToCipherVector(t *testing.T) {
	_, pubKey := libunlynx.GenKey()

	testCipherVect := make(libunlynx.CipherVector, 1)
	expRes := []int64{1}
	for i, p := range expRes {
		testCipherVect[i] = *libunlynx.EncryptInt(pubKey, p)
	}
	processResponse1 := libunlynx.ProcessResponse{GroupByEnc: testCipherVect, WhereEnc: testCipherVect, AggregatingAttributes: testCipherVect}

	testCipherVect1 := make(libunlynx.CipherVector, 1)
	expRes1 := []int64{1}
	for i, p := range expRes1 {
		testCipherVect1[i] = *libunlynx.EncryptInt(pubKey, p)
	}
	processResponse2 := libunlynx.ProcessResponse{GroupByEnc: testCipherVect1, WhereEnc: testCipherVect1, AggregatingAttributes: testCipherVect1}

	testCipherVect2 := make(libunlynx.CipherVector, 1)
	expRes2 := []int64{2}
	for i, p := range expRes2 {
		testCipherVect2[i] = *libunlynx.EncryptInt(pubKey, p)
	}
	processResponse3 := libunlynx.ProcessResponse{GroupByEnc: testCipherVect2, WhereEnc: testCipherVect2, AggregatingAttributes: testCipherVect2}

	mapi := make([]libunlynx.ProcessResponse, 4)
	mapi[0] = processResponse1
	mapi[1] = processResponse2
	mapi[2] = processResponse3
	mapi[3] = processResponse1

	cv := protocolsunlynx.ProcessResponseToCipherVector(mapi)
	determCv := make(libunlynx.DeterministCipherVector, 0)
	for _, v := range cv {
		determCv = append(determCv, libunlynx.DeterministCipherText{Point: v.C})
	}

	result := protocolsunlynx.DeterCipherVectorToProcessResponseDet(determCv, mapi)
	for i, v := range result {
		assert.Equal(t, mapi[i], v.PR)
		assert.Equal(t, len(v.DetTagWhere), len(mapi[i].WhereEnc))
	}
}

func TestProcessResponseToMatrixCipherText(t *testing.T) {
	_, pubKey := libunlynx.GenKey()

	testCipherVect := make(libunlynx.CipherVector, 1)
	expRes := []int64{1}
	for i, p := range expRes {
		testCipherVect[i] = *libunlynx.EncryptInt(pubKey, p)
	}
	processResponse1 := libunlynx.ProcessResponse{GroupByEnc: testCipherVect, WhereEnc: testCipherVect, AggregatingAttributes: testCipherVect}

	testCipherVect1 := make(libunlynx.CipherVector, 1)
	expRes1 := []int64{1}
	for i, p := range expRes1 {
		testCipherVect1[i] = *libunlynx.EncryptInt(pubKey, p)
	}
	processResponse2 := libunlynx.ProcessResponse{GroupByEnc: testCipherVect1, WhereEnc: testCipherVect1, AggregatingAttributes: testCipherVect1}

	testCipherVect2 := make(libunlynx.CipherVector, 1)
	expRes2 := []int64{2}
	for i, p := range expRes2 {
		testCipherVect2[i] = *libunlynx.EncryptInt(pubKey, p)
	}
	processResponse3 := libunlynx.ProcessResponse{GroupByEnc: testCipherVect2, WhereEnc: testCipherVect2, AggregatingAttributes: testCipherVect2}

	mapi := make([]libunlynx.ProcessResponse, 4)
	mapi[0] = processResponse1
	mapi[1] = processResponse2
	mapi[2] = processResponse3
	mapi[3] = processResponse1

	cv, lengths := protocolsunlynx.ProcessResponseToMatrixCipherText(mapi)
	mapiToTest := protocolsunlynx.MatrixCipherTextToProcessResponse(cv, lengths)
	for i, v := range mapi {
		assert.True(t, reflect.DeepEqual(mapiToTest[i], v))
	}
}

func TestAdaptCipherTextArray(t *testing.T) {
	_, pubKey := libunlynx.GenKey()

	k := 5
	cv := make(libunlynx.CipherVector, k)
	for i := range cv {
		cv[i] = *libunlynx.EncryptInt(pubKey, int64(i))
	}
	toTest := protocolsunlynx.AdaptCipherTextArray(cv)
	for i, v := range toTest {
		assert.True(t, reflect.DeepEqual(v[0], cv[i]))
	}
}
