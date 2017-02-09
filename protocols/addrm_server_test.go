package protocols_test

import (
	"testing"
	"time"

	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/dedis/onet.v1/network"
	"gopkg.in/dedis/onet.v1"
	"github.com/JoaoAndreSa/MedCo/lib"
	"github.com/JoaoAndreSa/MedCo/protocols"
	"gopkg.in/dedis/crypto.v0/random"
	"github.com/stretchr/testify/assert"
)

func TestAddRmServer(t *testing.T) {
	local := onet.NewLocalTest()
	_, _, tree := local.GenTree(1, true)

	defer local.CloseAll()

	rootInstance, err := local.CreateProtocol("AddRmServer", tree)
	if err != nil {
		t.Fatal("Couldn't start protocol:", err)
	}
	protocol := rootInstance.(*protocols.AddRmServerProtocol)

	secKey := network.Suite.Scalar().Pick(random.Stream)
	pubKey := network.Suite.Point().Mul(network.Suite.Point().Base(), secKey)

	secKeyAddRm := network.Suite.Scalar().Pick(random.Stream)

	//addition
	//secKeyAfter := network.Suite.Scalar().Add(secKey, secKeyAddRm)
	//substraction
	secKeyAfter := network.Suite.Scalar().Sub(secKey, secKeyAddRm)

	expectedResult := []int64{10, 10}
	cipherVect := *lib.EncryptIntVector(pubKey, expectedResult)
	cipherVect2 := *lib.NewCipherVector(len(cipherVect)).Add(cipherVect, cipherVect)

	// aggregation
	detResponses := make([]lib.ClientResponse, 3)
	detResponses[0] = lib.ClientResponse{ProbaGroupingAttributesEnc: cipherVect2, AggregatingAttributes: cipherVect}
	detResponses[1] = lib.ClientResponse{ProbaGroupingAttributesEnc: cipherVect, AggregatingAttributes: cipherVect}
	detResponses[2] = lib.ClientResponse{ProbaGroupingAttributesEnc: cipherVect2, AggregatingAttributes: cipherVect}

	log.LLvl1("CipherTexts to transform ")
	log.LLvl1(detResponses)

	protocol.TargetOfTransformation = detResponses
	protocol.Proofs = true
	feedback := protocol.FeedbackChannel
	protocol.Add = false
	protocol.KeyToRm = secKeyAddRm

	go protocol.Start()

	timeout := network.WaitRetry * time.Duration(network.MaxRetryConnect*5*2) * time.Millisecond

	select {
	case results := <-feedback:
		log.LLvl1("Results: ")
		log.LLvl1(results)
		decryptedResult := lib.DecryptIntVector(secKeyAfter, &results[0].AggregatingAttributes)
		assert.Equal(t, decryptedResult, expectedResult)
	case <-time.After(timeout):
		t.Fatal("Didn't finish in time")
	}
}
