package protocols_test

import (
	"reflect"
	"testing"
	"time"

	"github.com/lca1/unlynx/lib"
	"github.com/lca1/unlynx/protocols"
	"github.com/stretchr/testify/assert"
	"gopkg.in/dedis/crypto.v0/random"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/dedis/onet.v1/network"
)

func TestDeterministicTagging(t *testing.T) {
	local := onet.NewLocalTest()

	// You must register this protocol before creating the servers
	onet.GlobalProtocolRegister("DeterministicTaggingTest", NewDeterministicTaggingTest)
	_, entityList, tree := local.GenTree(5, true)

	defer local.CloseAll()

	rootInstance, err := local.CreateProtocol("DeterministicTaggingTest", tree)
	if err != nil {
		t.Fatal("Couldn't start protocol:", err)
	}

	protocol := rootInstance.(*protocols.DeterministicTaggingProtocol)

	aggregateKey := entityList.Aggregate

	//create data for test
	testCipherVect := make(lib.CipherVector, 1)
	expRes := []int64{1}
	for i, p := range expRes {
		testCipherVect[i] = *lib.EncryptInt(aggregateKey, p)
	}
	processResponse1 := lib.ProcessResponse{GroupByEnc: testCipherVect, WhereEnc: testCipherVect, AggregatingAttributes: testCipherVect}

	testCipherVect1 := make(lib.CipherVector, 1)
	expRes1 := []int64{1}
	for i, p := range expRes1 {
		testCipherVect1[i] = *lib.EncryptInt(aggregateKey, p)
	}
	processResponse2 := lib.ProcessResponse{GroupByEnc: testCipherVect1, WhereEnc: testCipherVect1, AggregatingAttributes: testCipherVect1}

	testCipherVect2 := make(lib.CipherVector, 1)
	expRes2 := []int64{2}
	for i, p := range expRes2 {
		testCipherVect2[i] = *lib.EncryptInt(aggregateKey, p)
	}
	processResponse3 := lib.ProcessResponse{GroupByEnc: testCipherVect2, WhereEnc: testCipherVect2, AggregatingAttributes: testCipherVect2}

	mapi := make([]lib.ProcessResponse, 4)
	mapi[0] = processResponse1
	mapi[1] = processResponse2
	mapi[2] = processResponse3
	mapi[3] = processResponse1

	log.Lvl1("Data to be Tagged ", mapi)

	protocol.TargetOfSwitch = &mapi
	feedback := protocol.FeedbackChannel
	go protocol.Start()

	timeout := network.WaitRetry * time.Duration(network.MaxRetryConnect*5*2) * time.Millisecond

	select {
	case encryptedResult := <-feedback:
		for _, v := range encryptedResult {
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
		for i, v := range encryptedResult {
			for j, w := range encryptedResult {
				if reflect.DeepEqual(v.DetTagGroupBy, w.DetTagGroupBy) && j != i {
					threeSame++
				}
				if reflect.DeepEqual(v.DetTagWhere, w.DetTagWhere) && j != i {
					threeSame1++
				}
			}
		}
		assert.True(t, threeSame == 6)
		assert.True(t, threeSame1 == 6)
		for _, v := range encryptedResult {
			log.Lvl1(v)
		}

	case <-time.After(timeout):
		t.Fatal("Didn't finish in time")
	}

}

// NewDeterministicTaggingTest is a special purpose protocol constructor specific to tests.
func NewDeterministicTaggingTest(tni *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {

	pi, err := protocols.NewDeterministicTaggingProtocol(tni)
	protocol := pi.(*protocols.DeterministicTaggingProtocol)
	protocol.Proofs = true
	clientPrivate := network.Suite.Scalar().Pick(random.Stream)
	protocol.SurveySecretKey = &clientPrivate

	return protocol, err
}
