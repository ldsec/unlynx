package protocols_test

import (
	"testing"
	"time"

	"github.com/JoaoAndreSa/MedCo/lib"
	"github.com/JoaoAndreSa/MedCo/protocols"
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
	protocol := rootInstance.(*protocols.LocalAggregationProtocol)

	secKey := network.Suite.Scalar().Pick(random.Stream)
	pubKey := network.Suite.Point().Mul(network.Suite.Point().Base(), secKey)
	cipherOne := *lib.EncryptInt(pubKey, 10)
	cipherVect := lib.CipherVector{cipherOne, cipherOne}
	cipherVect2 := *lib.NewCipherVector(len(cipherVect)).Add(cipherVect, cipherVect)

	// aggregation
	detResponses := make([]lib.ClientResponseDet, 3)
	detResponses[0] = lib.ClientResponseDet{CR: lib.ClientResponse{ProbaGroupingAttributesEnc: cipherVect2, AggregatingAttributes: cipherVect}, DetTag: lib.CipherVectorToDeterministicTag(cipherVect2, secKey, secKey, pubKey, true)}
	detResponses[1] = lib.ClientResponseDet{CR: lib.ClientResponse{ProbaGroupingAttributesEnc: cipherVect, AggregatingAttributes: cipherVect}, DetTag: lib.CipherVectorToDeterministicTag(cipherVect, secKey, secKey, pubKey, true)}
	detResponses[2] = lib.ClientResponseDet{CR: lib.ClientResponse{ProbaGroupingAttributesEnc: cipherVect2, AggregatingAttributes: cipherVect}, DetTag: lib.CipherVectorToDeterministicTag(cipherVect2, secKey, secKey, pubKey, true)}

	comparisonMap := make(map[lib.GroupingKey]lib.ClientResponse)
	for _, v := range detResponses {
		lib.AddInMap(comparisonMap, v.DetTag, v.CR)
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
