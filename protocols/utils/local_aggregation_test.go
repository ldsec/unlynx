package protocolsunlynxutils_test

import (
	"testing"
	"time"

	"github.com/ldsec/unlynx/lib"
	"github.com/ldsec/unlynx/protocols"
	"github.com/ldsec/unlynx/protocols/utils"
	"github.com/stretchr/testify/assert"
	"go.dedis.ch/kyber/v3/util/random"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/network"
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

	dtgb, err := protocolsunlynx.CipherVectorToDeterministicTag(cipherVect2, secKey, secKey, pubKey, true)
	detResponses[0] = libunlynx.FilteredResponseDet{Fr: libunlynx.FilteredResponse{GroupByEnc: cipherVect2, AggregatingAttributes: cipherVect}, DetTagGroupBy: dtgb}
	dtgb, err = protocolsunlynx.CipherVectorToDeterministicTag(cipherVect, secKey, secKey, pubKey, true)
	detResponses[1] = libunlynx.FilteredResponseDet{Fr: libunlynx.FilteredResponse{GroupByEnc: cipherVect, AggregatingAttributes: cipherVect}, DetTagGroupBy: dtgb}
	dtgb, err = protocolsunlynx.CipherVectorToDeterministicTag(cipherVect2, secKey, secKey, pubKey, true)
	detResponses[2] = libunlynx.FilteredResponseDet{Fr: libunlynx.FilteredResponse{GroupByEnc: cipherVect2, AggregatingAttributes: cipherVect}, DetTagGroupBy: dtgb}

	comparisonMap := make(map[libunlynx.GroupingKey]libunlynx.FilteredResponse)
	for _, v := range detResponses {
		libunlynx.AddInMap(comparisonMap, v.DetTagGroupBy, v.Fr)
	}

	protocol.TargetOfAggregation = detResponses
	protocol.Proofs = true
	feedback := protocol.FeedbackChannel

	go func() {
		err := protocol.Start()
		assert.NoError(t, err)
	}()

	timeout := network.WaitRetry * time.Duration(network.MaxRetryConnect*10) * time.Millisecond

	select {
	case results := <-feedback:
		assert.Equal(t, comparisonMap, results)
	case <-time.After(timeout):
		t.Fatal("Didn't finish in time")
	}
}
