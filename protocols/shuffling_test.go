package protocolsunlynx_test

import (
	"reflect"
	"testing"
	"time"

	"github.com/lca1/unlynx/lib/shuffle"

	"github.com/stretchr/testify/assert"

	"github.com/dedis/kyber"
	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
	"github.com/dedis/onet/network"
	"github.com/lca1/unlynx/lib"
	"github.com/lca1/unlynx/protocols"
)

var nbrNodes = 5
var priv = make([]kyber.Scalar, nbrNodes)
var pub = make([]kyber.Point, nbrNodes)
var groupPub = libunlynx.SuiTe.Point().Null()
var groupSec = libunlynx.SuiTe.Scalar().Zero()

var precomputes = make([][]libunlynx.CipherVectorScalar, nbrNodes)

func TestShuffling(t *testing.T) {
	defer log.AfterTest(t)

	local := onet.NewLocalTest(libunlynx.SuiTe)

	for i := 0; i < nbrNodes; i++ {
		priv[i] = libunlynx.SuiTe.Scalar().Pick(libunlynx.SuiTe.RandomStream())
		pub[i] = libunlynx.SuiTe.Point().Mul(priv[i], libunlynx.SuiTe.Point().Base())
		groupPub.Add(groupPub, pub[i])
		groupSec.Add(groupSec, priv[i])
	}
	for i := 0; i < nbrNodes; i++ {
		privBytes, _ := priv[i].MarshalBinary()
		precomputes[i] = libunlynx.CreatePrecomputedRandomize(libunlynx.SuiTe.Point().Base(), groupPub, libunlynx.SuiTe.XOF(privBytes), 4, 10)
	}
	aggregateKey := groupPub

	// You must register this protocol before creating the servers
	if _, err := onet.GlobalProtocolRegister("ShufflingTest", NewShufflingTest); err != nil {
		log.Fatal("Failed to register the <ShufflingTest> protocol:", err)
	}
	_, _, tree := local.GenTree(nbrNodes, true)
	defer local.CloseAll()

	rootInstance, _ := local.CreateProtocol("ShufflingTest", tree)
	protocol := rootInstance.(*protocolsunlynx.ShufflingProtocol)

	//create data
	testCipherVect := make(libunlynx.CipherVector, 1)
	expRes := []int64{1}
	for i, p := range expRes {
		testCipherVect[i] = *libunlynx.EncryptInt(aggregateKey, p)
	}
	processResponse := libunlynx.ProcessResponse{GroupByEnc: testCipherVect, WhereEnc: testCipherVect, AggregatingAttributes: testCipherVect}

	testCipherVect1 := make(libunlynx.CipherVector, 1)
	expRes1 := []int64{1}
	for i, p := range expRes1 {
		testCipherVect1[i] = *libunlynx.EncryptInt(aggregateKey, p)
	}
	processResponse1 := libunlynx.ProcessResponse{GroupByEnc: testCipherVect1, WhereEnc: testCipherVect1, AggregatingAttributes: testCipherVect1}

	testCipherVect2 := make(libunlynx.CipherVector, 1)
	expRes2 := []int64{2}
	for i, p := range expRes2 {
		testCipherVect2[i] = *libunlynx.EncryptInt(aggregateKey, p)
	}
	processResponse2 := libunlynx.ProcessResponse{GroupByEnc: testCipherVect2, WhereEnc: testCipherVect2, AggregatingAttributes: testCipherVect2}

	mapi := make([]libunlynx.ProcessResponse, 4)
	mapi[0] = processResponse
	mapi[1] = processResponse1
	mapi[2] = processResponse2
	mapi[3] = processResponse

	cv, lengths := protocolsunlynx.ProcessResponseToMatrixCipherText(mapi)
	protocol.ShuffleTarget = &cv
	protocol.CollectiveKey = groupPub

	protocol.Proofs = true
	protocol.ProofFunc = func(shuffleTarget, shuffledData []libunlynx.CipherVector, collectiveKey kyber.Point, beta [][]kyber.Scalar, pi []int) *libunlynxshuffle.PublishedShufflingProof {
		proof := libunlynxshuffle.ShuffleProofCreation(shuffleTarget, shuffledData, libunlynx.SuiTe.Point().Base(), collectiveKey, beta, pi)
		return &proof
	}

	feedback := protocol.FeedbackChannel
	go func() {
		if err := protocol.Start(); err != nil {
			log.Fatal("Error to start <Shuffling> protocol")
		}
	}()

	timeout := network.WaitRetry * time.Duration(network.MaxRetryConnect*10) * time.Millisecond

	select {
	case encryptedResult := <-feedback:
		formatedResult := protocolsunlynx.MatrixCipherTextToProcessResponse(encryptedResult, lengths)

		for _, v := range formatedResult {
			decryptedVAggr := libunlynx.DecryptIntVector(groupSec, &v.AggregatingAttributes)
			decryptedVGrp := libunlynx.DecryptIntVector(groupSec, &v.GroupByEnc)
			present := false
			for _, w := range mapi {
				decryptedWAggr := libunlynx.DecryptIntVector(groupSec, &w.AggregatingAttributes)
				decryptedWGrp := libunlynx.DecryptIntVector(groupSec, &w.GroupByEnc)
				if reflect.DeepEqual(decryptedWAggr, decryptedVAggr) && reflect.DeepEqual(decryptedWGrp, decryptedVGrp) {
					present = true
				}
			}
			assert.True(t, present, "Error during shuffling")
		}

	case <-time.After(timeout):
		t.Fatal("Didn't finish in time")
	}

}

// NewShufflingTest is a special purpose protocol constructor specific to tests.
func NewShufflingTest(tni *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	pi, err := protocolsunlynx.NewShufflingProtocol(tni)
	protocol := pi.(*protocolsunlynx.ShufflingProtocol)

	protocol.CollectiveKey = groupPub
	protocol.Precomputed = precomputes[tni.Index()]

	protocol.Proofs = true
	protocol.ProofFunc = func(shuffleTarget, shuffledData []libunlynx.CipherVector, collectiveKey kyber.Point, beta [][]kyber.Scalar, pi []int) *libunlynxshuffle.PublishedShufflingProof {
		proof := libunlynxshuffle.ShuffleProofCreation(shuffleTarget, shuffledData, libunlynx.SuiTe.Point().Base(), collectiveKey, beta, pi)
		return &proof
	}
	return protocol, err
}
