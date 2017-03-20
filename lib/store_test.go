package lib_test

import (
	"github.com/JoaoAndreSa/MedCo/lib"
	"github.com/stretchr/testify/assert"
	"gopkg.in/dedis/crypto.v0/random"
	"gopkg.in/dedis/onet.v1/network"
	"testing"
	"strconv"
	"github.com/dedis/cothority/log"
)

// TestStoring tests survey store and its methods.
func TestStoring(t *testing.T) {

	// construction of variables
	secKey := network.Suite.Scalar().Pick(random.Stream)
	pubKey := network.Suite.Point().Mul(network.Suite.Point().Base(), secKey)

	tab1 := []int64{1, 2, 3, 6}
	testCipherVect1Map := make(map[string]lib.CipherText)
	for i,v := range tab1{
		testCipherVect1Map[strconv.Itoa(i)] = *lib.EncryptInt(pubKey, v)
	}
	testCipherVect1 := *lib.EncryptIntVector(pubKey, tab1)

	tab2 := []int64{2, 4, 8, 6}
	testCipherVect2Map := make(map[string]lib.CipherText)
	for i,v := range tab2{
		testCipherVect2Map[strconv.Itoa(i)] = *lib.EncryptInt(pubKey, v)
	}
	testCipherVect2 := *lib.EncryptIntVector(pubKey, tab2)

	tab3 := []int64{2, 4}
	testCipherVect3Map := make(map[string]lib.CipherText)
	for i,v := range tab3{
		testCipherVect3Map[strconv.Itoa(i)] = *lib.EncryptInt(pubKey, v)
	}
	//testCipherVect2 := *lib.EncryptIntVector(pubKey, tab2)

	tabGrp := []int64{0,1}
	testGrpMap := make(map[string]lib.CipherText)
	for i,v := range tabGrp{
		testGrpMap[strconv.Itoa(i)] = *lib.EncryptInt(pubKey, v)
	}

	tabGrp1 := []int64{0,1}
	testGrpMap1 := make(map[string]int64)
	for i,v := range tabGrp1{
		testGrpMap1[strconv.Itoa(i)] = v
	}

	dummySurveyCreationQuery := lib.SurveyCreationQuery{Sum:[]string{"0","1","2","3"}, GroupBy:[]string{"0","1"}, Where:[]lib.WhereQueryAttribute{{"0", lib.CipherText{}},{"1", lib.CipherText{}}}}
	// constructor test
	storage := lib.NewStore()

	// AddAggregate & GetAggregateLoc Test
	storage.InsertDpResponse(lib.DpResponse{GroupByEnc: testGrpMap, WhereClear:testGrpMap1, AggregatingAttributes: testCipherVect1Map}, true,dummySurveyCreationQuery)
	log.LLvl1("first insert")
	assert.True(t, (len(storage.PullDpResponses()) == 1))
	assert.Empty(t, storage.DpResponses)

	storage.InsertDpResponse(lib.DpResponse{GroupByClear: testGrpMap1, WhereClear:testGrpMap1, AggregatingAttributes: testCipherVect2Map}, true, dummySurveyCreationQuery)
	storage.InsertDpResponse(lib.DpResponse{GroupByClear: testGrpMap1, WhereClear:testGrpMap1, AggregatingAttributes: testCipherVect2Map}, true, dummySurveyCreationQuery)
	storage.InsertDpResponse(lib.DpResponse{GroupByClear: testGrpMap1, WhereClear:testGrpMap1, AggregatingAttributes: testCipherVect2Map}, true, dummySurveyCreationQuery)
	sum := *lib.NewCipherVector(len(testCipherVect2)).Add(testCipherVect2, testCipherVect2)
	sum = *sum.Add(sum, testCipherVect2)
	result := storage.PullDpResponses()
	assert.True(t, (len(result) == 1))
	assert.Equal(t, result[0].AggregatingAttributes[0], sum)

	//empty the local aggregation results
	storage.PullLocallyAggregatedResponses()
	log.LLvl1("PUREE")
	// GROUPING
	storage = lib.NewStore()
	storage.InsertDpResponse(lib.DpResponse{GroupByClear: testGrpMap1, GroupByEnc: testGrpMap, WhereClear:testGrpMap1, WhereEnc: testGrpMap,   AggregatingAttributes: testCipherVect2Map}, true, dummySurveyCreationQuery)
	storage.InsertDpResponse(lib.DpResponse{GroupByEnc: testGrpMap, AggregatingAttributes: testCipherVect2Map}, false, dummySurveyCreationQuery)
	storage.InsertDpResponse(lib.DpResponse{WhereEnc: testGrpMap, AggregatingAttributes: testCipherVect1Map}, true,dummySurveyCreationQuery)

	filteredResponses := []lib.FilteredResponse{{GroupByEnc: testCipherVect2, AggregatingAttributes: testCipherVect2},
		{GroupByEnc: testCipherVect1, AggregatingAttributes: testCipherVect2}, {GroupByEnc: testCipherVect2, AggregatingAttributes: testCipherVect1}}

	assert.True(t, len(storage.DpResponses) == 3)

	// Shuffling related part
	listToShuffle := storage.PullDpResponses()
	storage.PushShuffledProcessResponses(listToShuffle)
	assert.True(t, len(storage.ShuffledProcessResponses) == len(listToShuffle))
	assert.Empty(t, storage.DpResponses)

	listShuffled := storage.PullShuffledProcessResponses()
	assert.True(t, len(listShuffled) == len(listToShuffle))
	assert.Empty(t, storage.ShuffledProcessResponses)

	// deterministic tagging related part
	detResponses := make([]lib.FilteredResponseDet, 3)
	detResponses[0] = lib.FilteredResponseDet{Fr: lib.FilteredResponse{GroupByEnc: testCipherVect2, AggregatingAttributes: testCipherVect1}, DetTagGroupBy: lib.CipherVectorToDeterministicTag(testCipherVect2, secKey, secKey, pubKey, true)}
	detResponses[1] = lib.FilteredResponseDet{Fr: lib.FilteredResponse{GroupByEnc: testCipherVect1, AggregatingAttributes: testCipherVect1}, DetTagGroupBy: lib.CipherVectorToDeterministicTag(testCipherVect1, secKey, secKey, pubKey, true)}
	detResponses[2] = lib.FilteredResponseDet{Fr: lib.FilteredResponse{GroupByEnc: testCipherVect2, AggregatingAttributes: testCipherVect1}, DetTagGroupBy: lib.CipherVectorToDeterministicTag(testCipherVect2, secKey, secKey, pubKey, true)}

	storage.PushDeterministicFilteredResponses(detResponses, "ServerTest", true)

	assert.True(t, len(storage.PullLocallyAggregatedResponses()) == 2)
	assert.Empty(t, storage.LocAggregatedProcessResponse, 0)

	// collective aggregation part
	detResponsesMap := make(map[lib.GroupingKey]lib.FilteredResponse, 3)
	detResponsesMap[detResponses[0].DetTagGroupBy] = detResponses[0].Fr
	detResponsesMap[detResponses[1].DetTagGroupBy] = detResponses[1].Fr
	detResponsesMap[detResponses[2].DetTagGroupBy] = detResponses[2].Fr
	storage.PushCothorityAggregatedFilteredResponses(detResponsesMap)

	assert.True(t, len(storage.PullCothorityAggregatedFilteredResponses(false, lib.CipherText{})) == 2)
	assert.Empty(t, storage.GroupedDeterministicFilteredResponses, 0)

	//key switching related part
	storage.PushQuerierKeyEncryptedResponses(filteredResponses)
	results := storage.PullDeliverableResults()

	assert.True(t, len(results) == 3)
	assert.Empty(t, len(storage.DeliverableResults), 0)

}

func TestConvertDataToMap(t *testing.T) {
	test := []int64{0,1,2,3,4}

	result := make(map[string]int64)
	result["g0"] = 0
	result["g1"] = 1
	result["g2"] = 2
	result["g3"] = 3
	result["g4"] = 4

	assert.Equal(t, result, lib.ConvertDataToMap(test,"g",0), "Wrong map conversion")
}
