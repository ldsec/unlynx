package lib_test

import (
	"github.com/JoaoAndreSa/MedCo/lib"
	"github.com/stretchr/testify/assert"
	"gopkg.in/dedis/crypto.v0/random"
	"gopkg.in/dedis/onet.v1/network"
	"testing"
)

// TestStoring tests survey store and its methods.
func TestStoring(t *testing.T) {

	// construction of variables
	secKey := network.Suite.Scalar().Pick(random.Stream)
	pubKey := network.Suite.Point().Mul(network.Suite.Point().Base(), secKey)

	tab1 := []int64{1, 2, 3, 6}
	testCipherVect1 := *lib.EncryptIntVector(pubKey, tab1)

	tab2 := []int64{2, 4, 8, 6}
	testCipherVect2 := *lib.EncryptIntVector(pubKey, tab2)

	// constructor test
	storage := lib.NewStore()

	// AddAggregate & GetAggregateLoc Test
	storage.InsertClientResponse(lib.ClientResponse{"", lib.CipherVector{}, testCipherVect1})

	assert.True(t, (len(storage.PullClientResponses()) == 1))
	assert.Empty(t, storage.ClientResponses)

	//empty the local aggregation results
	storage.PullLocallyAggregatedResponses()

	// GROUPING
	storage = lib.NewStore()
	storage.InsertClientResponse(lib.ClientResponse{ProbaGroupingAttributesEnc: testCipherVect2, AggregatingAttributes: testCipherVect2})
	storage.InsertClientResponse(lib.ClientResponse{ProbaGroupingAttributesEnc: testCipherVect1, AggregatingAttributes: testCipherVect2})
	storage.InsertClientResponse(lib.ClientResponse{ProbaGroupingAttributesEnc: testCipherVect2, AggregatingAttributes: testCipherVect1})

	clientResponses := []lib.ClientResponse{{ProbaGroupingAttributesEnc: testCipherVect2, AggregatingAttributes: testCipherVect2},
		{ProbaGroupingAttributesEnc: testCipherVect1, AggregatingAttributes: testCipherVect2}, {ProbaGroupingAttributesEnc: testCipherVect2, AggregatingAttributes: testCipherVect1}}

	assert.True(t, len(storage.ClientResponses) == 3)

	// Shuffling related part
	listToShuffle := storage.PullClientResponses()
	storage.PushShuffledClientResponses(listToShuffle)
	assert.True(t, len(storage.ShuffledClientResponses) == len(listToShuffle))
	assert.Empty(t, storage.ClientResponses)

	listShuffled := storage.PullShuffledClientResponses()
	assert.True(t, len(listShuffled) == len(listToShuffle))
	assert.Empty(t, storage.ShuffledClientResponses)

	// deterministic tagging related part
	detResponses := make([]lib.ClientResponseDet, 3)
	detResponses[0] = lib.ClientResponseDet{CR: lib.ClientResponse{ProbaGroupingAttributesEnc: testCipherVect2, AggregatingAttributes: testCipherVect1}, DetTag: lib.CipherVectorToDeterministicTag(testCipherVect2, secKey, secKey, pubKey, true)}
	detResponses[1] = lib.ClientResponseDet{CR: lib.ClientResponse{ProbaGroupingAttributesEnc: testCipherVect1, AggregatingAttributes: testCipherVect1}, DetTag: lib.CipherVectorToDeterministicTag(testCipherVect1, secKey, secKey, pubKey, true)}
	detResponses[2] = lib.ClientResponseDet{CR: lib.ClientResponse{ProbaGroupingAttributesEnc: testCipherVect2, AggregatingAttributes: testCipherVect1}, DetTag: lib.CipherVectorToDeterministicTag(testCipherVect2, secKey, secKey, pubKey, true)}

	storage.PushDeterministicClientResponses(detResponses, "ServerTest", true)

	assert.True(t, len(storage.PullLocallyAggregatedResponses()) == 2)
	assert.Empty(t, storage.LocAggregatedClientResponse, 0)

	// collective aggregation part
	detResponsesMap := make(map[lib.GroupingKey]lib.ClientResponse, 3)
	detResponsesMap[detResponses[0].DetTag] = detResponses[0].CR
	detResponsesMap[detResponses[1].DetTag] = detResponses[1].CR
	detResponsesMap[detResponses[2].DetTag] = detResponses[2].CR
	storage.PushCothorityAggregatedClientResponses(detResponsesMap)

	assert.True(t, len(storage.PullCothorityAggregatedClientResponses()) == 2)
	assert.Empty(t, storage.GroupedDeterministicClientResponses, 0)

	//key switching related part
	storage.PushQuerierKeyEncryptedResponses(clientResponses)
	results := storage.PullDeliverableResults()

	assert.True(t, len(results) == 3)
	assert.Empty(t, len(storage.DeliverableResults), 0)

}
