package libunlynxaggr_test

import (
	"testing"

	"github.com/lca1/unlynx/lib/aggregation"
	"github.com/stretchr/testify/assert"

	"github.com/dedis/kyber/util/key"
	"github.com/lca1/unlynx/lib"
)

func TestAggregationProof(t *testing.T) {
	keys := key.NewKeyPair(libunlynx.SuiTe)
	pubKey, _ := keys.Public, keys.Private

	tab1 := []int64{1, 2, 3, 6}
	testCV1 := *libunlynx.EncryptIntVector(pubKey, tab1)

	tab2 := []int64{1, 2, 3, 6}
	testCV2 := *libunlynx.EncryptIntVector(pubKey, tab2)

	aggr1 := testCV1.Acum()
	aggr2 := testCV2.Acum()

	PublishedAggregationProof := libunlynxaggr.AggregationProofCreation(testCV1, aggr1)
	assert.True(t, libunlynxaggr.AggregationProofVerification(PublishedAggregationProof))

	PublishedAggregationProof = libunlynxaggr.AggregationProofCreation(testCV1, testCV1[0])
	assert.False(t, libunlynxaggr.AggregationProofVerification(PublishedAggregationProof))

	PublishedAggregationListProof := libunlynxaggr.AggregationListProofCreation([]libunlynx.CipherVector{testCV1, testCV2}, libunlynx.CipherVector{aggr1, aggr2})
	assert.True(t, libunlynxaggr.AggregationListProofVerification(PublishedAggregationListProof, 1.0))

}
