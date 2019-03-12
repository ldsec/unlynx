package protocolsunlynxutils_test

import (
	"testing"
	"time"

	"github.com/dedis/kyber/util/random"
	"github.com/dedis/onet"
	"github.com/dedis/onet/network"
	"github.com/lca1/unlynx/lib"
	"github.com/lca1/unlynx/lib/tools"
	"github.com/lca1/unlynx/protocols"
	"github.com/lca1/unlynx/protocols/utils"
	"github.com/stretchr/testify/assert"
	"go.dedis.ch/onet/log"
)

func TestLocalAggregation(t *testing.T) {
	local := onet.NewLocalTest(libunlynx.SuiTe)
	_, _, tree := local.GenTree(1, true)

	defer local.CloseAll()

	rootInstance, err := local.CreateProtocol("LocalAggregation", tree)
	if err != nil {
		t.Fatal("Couldn't start protocol:", err)
	}
	protocol := rootInstance.(*protocolsunlynxutils.LocalAggregationProtocol)

	secKey := libunlynx.SuiTe.Scalar().Pick(random.New())
	pubKey := libunlynx.SuiTe.Point().Mul(secKey, libunlynx.SuiTe.Point().Base())
	cipherOne := *libunlynx.EncryptInt(pubKey, 10)
	cipherVect := libunlynx.CipherVector{cipherOne, cipherOne}
	cipherVect2 := *libunlynx.NewCipherVector(len(cipherVect))
	cipherVect2.Add(cipherVect, cipherVect)

	// aggregation
	detResponses := make([]libunlynx.FilteredResponseDet, 3)
	detResponses[0] = libunlynx.FilteredResponseDet{Fr: libunlynx.FilteredResponse{GroupByEnc: cipherVect2, AggregatingAttributes: cipherVect}, DetTagGroupBy: protocolsunlynx.CipherVectorToDeterministicTag(cipherVect2, secKey, secKey, pubKey, true)}
	detResponses[1] = libunlynx.FilteredResponseDet{Fr: libunlynx.FilteredResponse{GroupByEnc: cipherVect, AggregatingAttributes: cipherVect}, DetTagGroupBy: protocolsunlynx.CipherVectorToDeterministicTag(cipherVect, secKey, secKey, pubKey, true)}
	detResponses[2] = libunlynx.FilteredResponseDet{Fr: libunlynx.FilteredResponse{GroupByEnc: cipherVect2, AggregatingAttributes: cipherVect}, DetTagGroupBy: protocolsunlynx.CipherVectorToDeterministicTag(cipherVect2, secKey, secKey, pubKey, true)}

	comparisonMap := make(map[libunlynx.GroupingKey]libunlynx.FilteredResponse)
	for _, v := range detResponses {
		libunlynxtools.AddInMap(comparisonMap, v.DetTagGroupBy, v.Fr)
	}

	protocol.TargetOfAggregation = detResponses
	protocol.Proofs = true
	feedback := protocol.FeedbackChannel

	go func() {
		if err := protocol.Start(); err != nil {
			log.Fatal("Error to Start <LocalAggregation> protocol")
		}
	}()

	timeout := network.WaitRetry * time.Duration(network.MaxRetryConnect*5*2) * time.Millisecond

	select {
	case results := <-feedback:
		assert.Equal(t, comparisonMap, results)
	case <-time.After(timeout):
		t.Fatal("Didn't finish in time")
	}
}
