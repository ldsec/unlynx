package protocols_test

import (
	"reflect"
	"testing"
	"time"

	"github.com/LCA1/UnLynx/lib"
	"github.com/LCA1/UnLynx/protocols"
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/crypto.v0/random"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/dedis/onet.v1/network"
)

var nbrNodes = 5
var priv = make([]abstract.Scalar, nbrNodes)
var pub = make([]abstract.Point, nbrNodes)
var groupPub = network.Suite.Point().Null()
var groupSec = network.Suite.Scalar().Zero()

var precomputes = make([][]lib.CipherVectorScalar, nbrNodes)

func TestShuffling(t *testing.T) {
	defer log.AfterTest(t)
	local := onet.NewLocalTest()
	log.TestOutput(testing.Verbose(), 1)

	for i := 0; i < nbrNodes; i++ {
		priv[i] = network.Suite.Scalar().Pick(random.Stream)
		pub[i] = network.Suite.Point().Mul(network.Suite.Point().Base(), priv[i])
		groupPub.Add(groupPub, pub[i])
		groupSec.Add(groupSec, priv[i])
	}
	for i := 0; i < nbrNodes; i++ {
		precomputes[i] = lib.CreatePrecomputedRandomize(network.Suite.Point().Base(), groupPub, network.Suite.Cipher(priv[i].Bytes()), 4, 10)
	}
	aggregateKey := groupPub

	// You must register this protocol before creating the servers
	onet.GlobalProtocolRegister("ShufflingTest", NewShufflingTest)
	_, _, tree := local.GenTree(nbrNodes, true)
	defer local.CloseAll()

	rootInstance, _ := local.CreateProtocol("ShufflingTest", tree)
	protocol := rootInstance.(*protocols.ShufflingProtocol)

	//create data
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

	log.LLvl1("Data before shuffling ", mapi)

	protocol.TargetOfShuffle = &mapi
	protocol.CollectiveKey = groupPub
	protocol.Proofs = true

	feedback := protocol.FeedbackChannel
	go protocol.Start()

	timeout := network.WaitRetry * time.Duration(network.MaxRetryConnect*5*2) * time.Millisecond

	select {
	case encryptedResult := <-feedback:

		for _, v := range encryptedResult {
			decryptedVAggr := lib.DecryptIntVector(groupSec, &v.AggregatingAttributes)
			log.LLvl1(decryptedVAggr)
			decryptedVGrp := lib.DecryptIntVector(groupSec, &v.GroupByEnc)
			present := false
			for _, w := range mapi {
				decryptedWAggr := lib.DecryptIntVector(groupSec, &w.AggregatingAttributes)
				decryptedWGrp := lib.DecryptIntVector(groupSec, &w.GroupByEnc)
				if reflect.DeepEqual(decryptedWAggr, decryptedVAggr) && reflect.DeepEqual(decryptedWGrp, decryptedVGrp) {
					present = true
				}
			}
			if !present {
				t.Error("ERROR")
			}
			log.LLvl1(v)
		}

	case <-time.After(timeout):
		t.Fatal("Didn't finish in time")
	}

}

// NewShufflingTest is a special purpose protocol constructor specific to tests.
func NewShufflingTest(tni *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	pi, err := protocols.NewShufflingProtocol(tni)
	protocol := pi.(*protocols.ShufflingProtocol)
	protocol.CollectiveKey = groupPub
	protocol.Precomputed = precomputes[tni.Index()]
	protocol.Proofs = true

	return protocol, err
}
