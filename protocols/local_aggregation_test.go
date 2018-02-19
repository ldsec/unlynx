package protocolsUnLynx_test

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
	protocol := rootInstance.(*protocolsUnLynx.LocalAggregationProtocol)

	secKey := network.Suite.Scalar().Pick(random.Stream)
	pubKey := network.Suite.Point().Mul(network.Suite.Point().Base(), secKey)
	cipherOne := *libUnLynx.EncryptInt(pubKey, 10)
	cipherVect := libUnLynx.CipherVector{cipherOne, cipherOne}
	cipherVect2 := *libUnLynx.NewCipherVector(len(cipherVect))
	cipherVect2.Add(cipherVect, cipherVect)

	// aggregation
	detResponses := make([]libUnLynx.FilteredResponseDet, 3)
	detResponses[0] = libUnLynx.FilteredResponseDet{Fr: libUnLynx.FilteredResponse{GroupByEnc: cipherVect2, AggregatingAttributes: cipherVect}, DetTagGroupBy: libUnLynx.CipherVectorToDeterministicTag(cipherVect2, secKey, secKey, pubKey, true)}
	detResponses[1] = libUnLynx.FilteredResponseDet{Fr: libUnLynx.FilteredResponse{GroupByEnc: cipherVect, AggregatingAttributes: cipherVect}, DetTagGroupBy: libUnLynx.CipherVectorToDeterministicTag(cipherVect, secKey, secKey, pubKey, true)}
	detResponses[2] = libUnLynx.FilteredResponseDet{Fr: libUnLynx.FilteredResponse{GroupByEnc: cipherVect2, AggregatingAttributes: cipherVect}, DetTagGroupBy: libUnLynx.CipherVectorToDeterministicTag(cipherVect2, secKey, secKey, pubKey, true)}

	comparisonMap := make(map[libUnLynx.GroupingKey]libUnLynx.FilteredResponse)
	for _, v := range detResponses {
		libUnLynx.AddInMap(comparisonMap, v.DetTagGroupBy, v.Fr)
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
