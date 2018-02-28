package protocolsunlynx_test

import (
	"testing"
	"time"
	"github.com/dedis/kyber/util/random"
	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
	"github.com/dedis/onet/network"
	"github.com/lca1/unlynx/lib"
	"github.com/lca1/unlynx/protocols"
	"github.com/stretchr/testify/assert"
	"strconv"
)

func TestAddRmServer(t *testing.T) {
	local := onet.NewLocalTest(libunlynx.SuiTe)
	_, _, tree := local.GenTree(1, true)

	defer local.CloseAll()

	rootInstance, err := local.CreateProtocol("AddRmServer", tree)
	if err != nil {
		t.Fatal("Couldn't start protocol:", err)
	}
	protocol := rootInstance.(*protocolsunlynx.AddRmServerProtocol)

	secKey := libunlynx.SuiTe.Scalar().Pick(random.New())
	pubKey := libunlynx.SuiTe.Point().Mul(secKey, libunlynx.SuiTe.Point().Base())

	secKeyAddRm := libunlynx.SuiTe.Scalar().Pick(random.New())

	//addition
	//secKeyAfter := libunlynx.SuiTe.Scalar().Add(secKey, secKeyAddRm)
	//substraction
	secKeyAfter := libunlynx.SuiTe.Scalar().Sub(secKey, secKeyAddRm)

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
	encrypted := make(map[string]libunlynx.CipherText)
	for i, v := range tab {
		encrypted[strconv.Itoa(i)] = *libunlynx.EncryptInt(pubKey, v)
	}
	// aggregation
	dpResponses := make([]libunlynx.DpResponse, 3)
	dpResponses[0] = libunlynx.DpResponse{GroupByClear: notEncrypted, GroupByEnc: encrypted, WhereClear: notEncrypted, WhereEnc: encrypted, AggregatingAttributesClear: notEncrypted, AggregatingAttributesEnc: encrypted}
	dpResponses[1] = libunlynx.DpResponse{GroupByClear: notEncrypted, GroupByEnc: encrypted, WhereClear: notEncrypted, WhereEnc: encrypted, AggregatingAttributesClear: notEncrypted, AggregatingAttributesEnc: encrypted}
	dpResponses[2] = libunlynx.DpResponse{GroupByClear: notEncrypted, GroupByEnc: encrypted, WhereClear: notEncrypted, WhereEnc: encrypted, AggregatingAttributesClear: notEncrypted, AggregatingAttributesEnc: encrypted}

	log.Lvl1("CipherTexts to transform ")
	log.Lvl1(dpResponses)

	protocol.TargetOfTransformation = dpResponses
	protocol.Proofs = true
	feedback := protocol.FeedbackChannel
	protocol.Add = false
	protocol.KeyToRm = secKeyAddRm

	go protocol.Start()

	timeout := network.WaitRetry * time.Duration(network.MaxRetryConnect*5*2) * time.Millisecond

	select {
	case results := <-feedback:
		log.Lvl1("Results: ")
		log.Lvl1(results)
		decryptedResult := make(map[string]int64)
		for i, v := range results[0].AggregatingAttributesEnc {
			decryptedResult[i] = libunlynx.DecryptInt(secKeyAfter, v)
		}
		//decryptedResult := lib.DecryptIntVector(secKeyAfter, &results[0].AggregatingAttributesEnc)
		assert.Equal(t, decryptedResult, expectedResults)
	case <-time.After(timeout):
		t.Fatal("Didn't finish in time")

	}
}
