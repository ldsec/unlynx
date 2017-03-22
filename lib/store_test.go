package lib_test

import (
	"github.com/JoaoAndreSa/MedCo/lib"
	"github.com/stretchr/testify/assert"
	"gopkg.in/dedis/crypto.v0/random"
	"gopkg.in/dedis/onet.v1/network"
	"testing"
	"strconv"
)

// TestStoring tests survey store and its methods.
func TestStoring(t *testing.T) {

	// construction of variables
	secKey := network.Suite.Scalar().Pick(random.Stream)
	pubKey := network.Suite.Point().Mul(network.Suite.Point().Base(), secKey)

	// Generate data for aggregating attributes
	tab := []int64{1, 2, 3, 6}
	testAggr1 := *lib.EncryptIntVector(pubKey, tab)
	testAggrMap1 := make(map[string]lib.CipherText)
	for i := range tab {
		testAggrMap1[strconv.Itoa(i)] = testAggr1[i]
	}

	tab = []int64{2, 4, 8, 6}
	testAggr2 := *lib.EncryptIntVector(pubKey, tab)
	testAggrMap2 := make(map[string]lib.CipherText)
	for i := range tab {
		testAggrMap2[strconv.Itoa(i)] = testAggr2[i]
	}

	tab = []int64{2, 4}
	testAggr3 := *lib.EncryptIntVector(pubKey, tab)
	testAggrMap3 := make(map[string]lib.CipherText)
	for i := range tab {
		testAggrMap3[strconv.Itoa(i)] = testAggr3[i]
	}

	// Generate data for group by and where attributes
	tab = []int64{0,1}
	testEncMap := make(map[string]lib.CipherText)
	for i,v := range tab{
		testEncMap[strconv.Itoa(i)] = *lib.EncryptInt(pubKey, v)
	}

	tab = []int64{0,1}
	testClearMap := make(map[string]int64)
	for i,v := range tab {
		testClearMap[strconv.Itoa(i)] = v
	}

	dummySurveyCreationQuery := lib.SurveyCreationQuery{Sum:[]string{"0","1","2","3"}, GroupBy:[]string{"0","1"}, Where:[]lib.WhereQueryAttribute{{"0", lib.CipherText{}},{"1", lib.CipherText{}}}}

	// Constructor Test
	storage := lib.NewStore()

	// (1) Test Insert and Pull DpResponses
	storage.InsertDpResponse(lib.DpResponse{GroupByEnc: testEncMap, WhereClear: testClearMap, AggregatingAttributesEnc: testAggrMap1}, true, dummySurveyCreationQuery)

	assert.True(t, (len(storage.PullDpResponses()) == 1))
	assert.Empty(t, storage.DpResponses)

	// (2) Test Insert and Pull multiple DpResponses to check aggregation
	storage.InsertDpResponse(lib.DpResponse{GroupByClear: testClearMap, WhereClear: testClearMap, AggregatingAttributesEnc: testAggrMap2}, true, dummySurveyCreationQuery)
	storage.InsertDpResponse(lib.DpResponse{GroupByClear: testClearMap, WhereClear: testClearMap, AggregatingAttributesEnc: testAggrMap2}, true, dummySurveyCreationQuery)
	storage.InsertDpResponse(lib.DpResponse{GroupByClear: testClearMap, WhereClear: testClearMap, AggregatingAttributesEnc: testAggrMap2}, true, dummySurveyCreationQuery)

	sum := *lib.NewCipherVector(len(testAggr2)).Add(testAggr2, testAggr2)
	sum = *sum.Add(sum, testAggr2)

	result := storage.PullDpResponses()

	assert.True(t, (len(result) == 1))
	assert.Equal(t, result[0].AggregatingAttributes, sum)

	// (3) Test empty
	storage.PullLocallyAggregatedResponses()

	// (4) Test Insert and Pull DpResponses but with different parameters
	storage = lib.NewStore()

	storage.InsertDpResponse(lib.DpResponse{GroupByClear: testClearMap, GroupByEnc: testEncMap, WhereClear: testClearMap, WhereEnc: testEncMap, AggregatingAttributesEnc: testAggrMap2}, true, dummySurveyCreationQuery)
	storage.InsertDpResponse(lib.DpResponse{GroupByEnc: testEncMap, AggregatingAttributesEnc: testAggrMap2}, false, dummySurveyCreationQuery)
	storage.InsertDpResponse(lib.DpResponse{WhereEnc: testEncMap, AggregatingAttributesEnc: testAggrMap1}, true,dummySurveyCreationQuery)

	assert.True(t, len(storage.DpResponses) == 3)

	// (5) Test Shuffling pull and push functions
	listToShuffle := storage.PullDpResponses()
	storage.PushShuffledProcessResponses(listToShuffle)

	assert.True(t, len(storage.ShuffledProcessResponses) == len(listToShuffle))
	assert.Empty(t, storage.DpResponses)

	listShuffled := storage.PullShuffledProcessResponses()
	assert.True(t, len(listShuffled) == len(listToShuffle))
	assert.Empty(t, storage.ShuffledProcessResponses)

	// (5) Test Deterministic Tagging pull and push functions

	detResponses := make([]lib.FilteredResponseDet, 3)
	detResponses[0] = lib.FilteredResponseDet{Fr: lib.FilteredResponse{GroupByEnc: testAggr2, AggregatingAttributes: testAggr1}, DetTagGroupBy: lib.CipherVectorToDeterministicTag(testAggr2, secKey, secKey, pubKey, true)}
	detResponses[1] = lib.FilteredResponseDet{Fr: lib.FilteredResponse{GroupByEnc: testAggr1, AggregatingAttributes: testAggr1}, DetTagGroupBy: lib.CipherVectorToDeterministicTag(testAggr1, secKey, secKey, pubKey, true)}
	detResponses[2] = lib.FilteredResponseDet{Fr: lib.FilteredResponse{GroupByEnc: testAggr2, AggregatingAttributes: testAggr1}, DetTagGroupBy: lib.CipherVectorToDeterministicTag(testAggr2, secKey, secKey, pubKey, true)}

	storage.PushDeterministicFilteredResponses(detResponses, "ServerTest", true)

	assert.True(t, len(storage.PullLocallyAggregatedResponses()) == 2)
	assert.Empty(t, storage.LocAggregatedProcessResponse, 0)

	// (5) Test Collective Aggregation pull and push functions
	detResponsesMap := make(map[lib.GroupingKey]lib.FilteredResponse, 3)

	detResponsesMap[detResponses[0].DetTagGroupBy] = detResponses[0].Fr
	detResponsesMap[detResponses[1].DetTagGroupBy] = detResponses[1].Fr
	detResponsesMap[detResponses[2].DetTagGroupBy] = detResponses[2].Fr

	storage.PushCothorityAggregatedFilteredResponses(detResponsesMap)

	assert.True(t, len(storage.PullCothorityAggregatedFilteredResponses(false, lib.CipherText{})) == 2)
	assert.Empty(t, storage.GroupedDeterministicFilteredResponses, 0)

	// (5) Test KeySwitching pull and push functions
	filteredResponses := []lib.FilteredResponse{{GroupByEnc: testAggr2, AggregatingAttributes: testAggr2},
		{GroupByEnc: testAggr1, AggregatingAttributes: testAggr2}, {GroupByEnc: testAggr2, AggregatingAttributes: testAggr1}}
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
