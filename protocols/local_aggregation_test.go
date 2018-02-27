package protocolsunlynx_test

import (
	"testing"
	"time"

	"github.com/lca1/unlynx/lib"
	"github.com/lca1/unlynx/protocols"
	"github.com/stretchr/testify/assert"
	"gopkg.in/dedis/crypto.v0/random"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/network"
)

func TestLocalAggregation(t *testing.T) {
	local := onet.NewLocalTest()
	_, _, tree := local.GenTree(1, true)

	defer local.CloseAll()

	rootInstance, err := local.CreateProtocol("LocalAggregation", tree)
	if err != nil {
		t.Fatal("Couldn't start protocol:", err)
	}
	protocol := rootInstance.(*protocolsunlynx.LocalAggregationProtocol)

	secKey := network.Suite.Scalar().Pick(random.Stream)
	pubKey := network.Suite.Point().Mul(network.Suite.Point().Base(), secKey)
	cipherOne := *libunlynx.EncryptInt(pubKey, 10)
	cipherVect := libunlynx.CipherVector{cipherOne, cipherOne}
	cipherVect2 := *libunlynx.NewCipherVector(len(cipherVect))
	cipherVect2.Add(cipherVect, cipherVect)

	// aggregation
	detResponses := make([]libunlynx.FilteredResponseDet, 3)
	detResponses[0] = libunlynx.FilteredResponseDet{Fr: libunlynx.FilteredResponse{GroupByEnc: cipherVect2, AggregatingAttributes: cipherVect}, DetTagGroupBy: libunlynx.CipherVectorToDeterministicTag(cipherVect2, secKey, secKey, pubKey, true)}
	detResponses[1] = libunlynx.FilteredResponseDet{Fr: libunlynx.FilteredResponse{GroupByEnc: cipherVect, AggregatingAttributes: cipherVect}, DetTagGroupBy: libunlynx.CipherVectorToDeterministicTag(cipherVect, secKey, secKey, pubKey, true)}
	detResponses[2] = libunlynx.FilteredResponseDet{Fr: libunlynx.FilteredResponse{GroupByEnc: cipherVect2, AggregatingAttributes: cipherVect}, DetTagGroupBy: libunlynx.CipherVectorToDeterministicTag(cipherVect2, secKey, secKey, pubKey, true)}

	comparisonMap := make(map[libunlynx.GroupingKey]libunlynx.FilteredResponse)
	for _, v := range detResponses {
		libunlynx.AddInMap(comparisonMap, v.DetTagGroupBy, v.Fr)
	}

	protocol.TargetOfAggregation = detResponses
	protocol.Proofs = true
	feedback := protocol.FeedbackChannel

	go protocol.Start()

	timeout := network.WaitRetry * time.Duration(network.MaxRetryConnect*5*2) * time.Millisecond

	select {
	case results := <-feedback:
		assert.Equal(t, comparisonMap, results)
	case <-time.After(timeout):
		t.Fatal("Didn't finish in time")
	}
}
