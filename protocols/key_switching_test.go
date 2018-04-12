package protocolsunlynx_test

import (
	"github.com/dedis/kyber/util/random"
	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
	"github.com/dedis/onet/network"
	"github.com/lca1/unlynx/lib"
	"github.com/lca1/unlynx/protocols"
	"reflect"
	"testing"
	"time"
)

func TestKeySwitching(t *testing.T) {
	local := onet.NewLocalTest(libunlynx.SuiTe)
	_, entityList, tree := local.GenTree(5, true)

	defer local.CloseAll()

	rootInstance, err := local.CreateProtocol("KeySwitching", tree)
	if err != nil {
		t.Fatal("Couldn't start protocol:", err)
	}
	protocol := rootInstance.(*protocolsunlynx.KeySwitchingProtocol)
	aggregateKey := entityList.Aggregate

	//create data
	expRes := []int64{1, 2, 3, 6}
	testCipherVect := *libunlynx.EncryptIntVector(aggregateKey, expRes)
	expRes1 := []int64{7, 8, 9, 7}
	testCipherVect1 := *libunlynx.EncryptIntVector(aggregateKey, expRes1)
	var tabi []libunlynx.FilteredResponse
	tabi = make([]libunlynx.FilteredResponse, 2)

	tabi[0] = libunlynx.FilteredResponse{GroupByEnc: testCipherVect1, AggregatingAttributes: testCipherVect}
	tabi[1] = libunlynx.FilteredResponse{GroupByEnc: testCipherVect, AggregatingAttributes: testCipherVect1}

	clientPrivate := libunlynx.SuiTe.Scalar().Pick(random.New())
	clientPublic := libunlynx.SuiTe.Point().Mul(clientPrivate, libunlynx.SuiTe.Point().Base())

	//protocol
	cv, lengths := protocolsunlynx.FilteredResponseToCipherVector(tabi)
	protocol.TargetOfSwitch = &cv
	protocol.TargetPublicKey = &clientPublic
	protocol.Proofs = true
	feedback := protocol.FeedbackChannel

	go protocol.Start()

	timeout := network.WaitRetry * time.Duration(network.MaxRetryConnect*5*2) * time.Millisecond

	select {
	case encryptedResult := <-feedback:
		adaptedResult := protocolsunlynx.CipherVectorToFilteredResponse(encryptedResult, lengths)
		cv1 := adaptedResult[0]
		res := libunlynx.DecryptIntVector(clientPrivate, &cv1.AggregatingAttributes)
		resGrp := libunlynx.DecryptIntVector(clientPrivate, &cv1.GroupByEnc)
		log.Lvl1("Recieved results (attributes) ", res)
		log.Lvl1("Recieved results (groups) ", resGrp)
		cv2 := adaptedResult[1]
		res1 := libunlynx.DecryptIntVector(clientPrivate, &cv2.AggregatingAttributes)
		resGrp1 := libunlynx.DecryptIntVector(clientPrivate, &cv2.GroupByEnc)
		log.Lvl1("Recieved results (attributes) ", res1)
		log.Lvl1("Recieved results (groups) ", resGrp1)

		if !reflect.DeepEqual(res, expRes) {
			t.Fatal("Wrong results, expected", expRes, "but got", res)
		} else {
			t.Log("Good results")
		}
	case <-time.After(timeout):
		t.Fatal("Didn't finish in time")
	}
}

func TestToBytesFromBytes(t *testing.T) {

}
