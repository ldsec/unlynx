package protocols_test

import (
	"testing"
	"time"

	"github.com/JoaoAndreSa/MedCo/lib"
	"github.com/JoaoAndreSa/MedCo/protocols"
	"github.com/stretchr/testify/assert"
	"gopkg.in/dedis/crypto.v0/random"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/dedis/onet.v1/network"
	"strconv"
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

	tab := []int64{10, 10}

	expectedResults := make(map[string]int64)
	expectedResults["0"] = 10
	expectedResults["1"] = 10
	//cipherVect := *lib.EncryptIntVector(pubKey, expectedResult)
	//cipherVect2 := *lib.NewCipherVector(len(cipherVect)).Add(cipherVect, cipherVect)

	//dummySurveyCreationQuery := lib.SurveyCreationQuery{Sum:[]string{"0","1"}, GroupBy:[]string{"0","1"}, Where:[]lib.WhereQueryAttribute{{"0", lib.CipherText{}},{"1", lib.CipherText{}}}}
	notEncrypted := make(map[string]int64)
	for i, v := range tab {
		notEncrypted[strconv.Itoa(i)] = v
	}
	encrypted := make(map[string]lib.CipherText)
	for i, v := range tab {
		encrypted[strconv.Itoa(i)] = *lib.EncryptInt(pubKey, v)
	}
	// aggregation
	dpResponses := make([]lib.DpResponse, 3)
	dpResponses[0] = lib.DpResponse{GroupByClear: notEncrypted, GroupByEnc: encrypted, WhereClear: notEncrypted, WhereEnc: encrypted, AggregatingAttributesClear: notEncrypted, AggregatingAttributesEnc: encrypted}
	dpResponses[1] = lib.DpResponse{GroupByClear: notEncrypted, GroupByEnc: encrypted, WhereClear: notEncrypted, WhereEnc: encrypted, AggregatingAttributesClear: notEncrypted, AggregatingAttributesEnc: encrypted}
	dpResponses[2] = lib.DpResponse{GroupByClear: notEncrypted, GroupByEnc: encrypted, WhereClear: notEncrypted, WhereEnc: encrypted, AggregatingAttributesClear: notEncrypted, AggregatingAttributesEnc: encrypted}

	log.LLvl1("CipherTexts to transform ")
	log.LLvl1(dpResponses)

	protocol.TargetOfTransformation = dpResponses
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
		decryptedResult := make(map[string]int64)
		for i, v := range results[0].AggregatingAttributesEnc {
			decryptedResult[i] = lib.DecryptInt(secKeyAfter, v)
		}
		//decryptedResult := lib.DecryptIntVector(secKeyAfter, &results[0].AggregatingAttributesEnc)
		assert.Equal(t, decryptedResult, expectedResults)
	case <-time.After(timeout):
		t.Fatal("Didn't finish in time")

	}
}
