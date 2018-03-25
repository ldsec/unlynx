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
	testCipherVect := make([]libunlynx.CipherText, 4)
	expRes := []int64{1, 1, 2, 1}
	for i, p := range expRes {
		testCipherVect[i] = *libunlynx.EncryptInt(aggregateKey, p)
	}

	log.Lvl1("Data to be Tagged ", testCipherVect)

	protocol.TargetOfSwitch = &testCipherVect
	feedback := protocol.FeedbackChannel
	go protocol.Start()

	timeout := network.WaitRetry * time.Duration(network.MaxRetryConnect*5*2) * time.Millisecond

	select {
	case encryptedResult := <-feedback:
		for i, v := range encryptedResult {
			if !reflect.DeepEqual(v.PR, testCipherVect[i]) {
				t.Fatal("DP responses changed and shouldn't")
			}
		}
		threeSame := 0
		threeSame1 := 0
		for i, v := range encryptedResult {
			for j, w := range encryptedResult {
				//TODO : Change when change the struct of ProcessResponseDet
				if j != i && reflect.DeepEqual(v.DetTagGroupBy, w.DetTagGroupBy) {
					threeSame++
				}
				if j != i && reflect.DeepEqual(v.DetTagWhere, w.DetTagWhere) {
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
	pi, err := protocolsunlynx.NewDeterministicTaggingProtocol(tni)
	protocol := pi.(*protocolsunlynx.DeterministicTaggingProtocol)
	protocol.Proofs = true
	clientPrivate := libunlynx.SuiTe.Scalar().Pick(random.New())
	protocol.SurveySecretKey = &clientPrivate

	return protocol, err
}
