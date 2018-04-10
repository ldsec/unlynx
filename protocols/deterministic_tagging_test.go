package protocolsunlynx_test

import (
	"github.com/dedis/kyber/util/random"
	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
	"github.com/dedis/onet/network"
	"github.com/lca1/unlynx/lib"
	"github.com/lca1/unlynx/protocols"
	"github.com/stretchr/testify/assert"
	"reflect"
	"testing"
	"time"
)

func TestDeterministicTagging(t *testing.T) {
	local := onet.NewLocalTest(libunlynx.SuiTe)

	// You must register this protocol before creating the servers
	onet.GlobalProtocolRegister("DeterministicTaggingTest", NewDeterministicTaggingTest)
	_, entityList, tree := local.GenTree(5, true)

	defer local.CloseAll()

	rootInstance, err := local.CreateProtocol("DeterministicTaggingTest", tree)
	if err != nil {
		t.Fatal("Couldn't start protocol:", err)
	}

	protocol := rootInstance.(*protocolsunlynx.DeterministicTaggingProtocol)

	aggregateKey := entityList.Aggregate

	//create data for test
	testCipherVect := make(libunlynx.CipherVector, 1)
	expRes := []int64{1}
	for i, p := range expRes {
		testCipherVect[i] = *libunlynx.EncryptInt(aggregateKey, p)
	}
	processResponse1 := libunlynx.ProcessResponse{GroupByEnc: testCipherVect, WhereEnc: testCipherVect, AggregatingAttributes: testCipherVect}

	testCipherVect1 := make(libunlynx.CipherVector, 1)
	expRes1 := []int64{1}
	for i, p := range expRes1 {
		testCipherVect1[i] = *libunlynx.EncryptInt(aggregateKey, p)
	}
	processResponse2 := libunlynx.ProcessResponse{GroupByEnc: testCipherVect1, WhereEnc: testCipherVect1, AggregatingAttributes: testCipherVect1}

	testCipherVect2 := make(libunlynx.CipherVector, 1)
	expRes2 := []int64{2}
	for i, p := range expRes2 {
		testCipherVect2[i] = *libunlynx.EncryptInt(aggregateKey, p)
	}
	processResponse3 := libunlynx.ProcessResponse{GroupByEnc: testCipherVect2, WhereEnc: testCipherVect2, AggregatingAttributes: testCipherVect2}

	mapi := make([]libunlynx.ProcessResponse, 4)
	mapi[0] = processResponse1
	mapi[1] = processResponse2
	mapi[2] = processResponse3
	mapi[3] = processResponse1

	log.Lvl1("Data to be Tagged ", mapi)
	cta := protocolsunlynx.PRToCipherTextArray(mapi)
	protocol.TargetOfSwitch = &cta
	feedback := protocol.FeedbackChannel
	go protocol.Start()

	timeout := network.WaitRetry * time.Duration(network.MaxRetryConnect*5*2) * time.Millisecond

	select {
	case encryptedResult := <-feedback:
		goodFormatResult := protocolsunlynx.DCVToProcessResponseDet(encryptedResult, mapi)
		for _, v := range goodFormatResult {
			present := false
			for _, w := range mapi {
				if reflect.DeepEqual(v.PR, w) {
					present = true
				}
			}
			if !present {
				t.Fatal("DP responses changed and shouldn't")
			}
		}
		threeSame := 0
		threeSame1 := 0
		for i, v := range goodFormatResult {
			for j, w := range goodFormatResult {
				if i != j {
					if reflect.DeepEqual(v.DetTagGroupBy, w.DetTagGroupBy) {
						threeSame++
					}
					if reflect.DeepEqual(v.DetTagWhere, w.DetTagWhere) {
						threeSame1++
					}
				}
			}
		}
		assert.True(t, threeSame == 6)
		assert.True(t, threeSame1 == 6)
		for _, v := range goodFormatResult {
			log.Lvl1(v)
		}

	case <-time.After(timeout):
		t.Fatal("Didn't finish in time")
	}

}

// NewDeterministicTaggingTest is a special purpose protocol constructor specific to tests.
func NewDeterministicTaggingTest(tni *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	pi, err := protocolsunlynx.NewDeterministicTaggingProtocol(tni)
	protocol := pi.(*protocolsunlynx.DeterministicTaggingProtocol)
	protocol.Proofs = true
	clientPrivate := libunlynx.SuiTe.Scalar().Pick(random.New())
	protocol.SurveySecretKey = &clientPrivate

	return protocol, err
}