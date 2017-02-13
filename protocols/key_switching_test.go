package protocols_test

import (
	"reflect"
	"testing"
	"time"

	"github.com/JoaoAndreSa/MedCo/lib"
	"github.com/JoaoAndreSa/MedCo/protocols"
	"gopkg.in/dedis/crypto.v0/random"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/dedis/onet.v1/network"
)

func TestKeySwitching(t *testing.T) {
	local := onet.NewLocalTest()
	_, entityList, tree := local.GenTree(5, true)

	defer local.CloseAll()

	rootInstance, err := local.CreateProtocol("KeySwitching", tree)
	if err != nil {
		t.Fatal("Couldn't start protocol:", err)
	}
	protocol := rootInstance.(*protocols.KeySwitchingProtocol)

	suite := network.Suite
	aggregateKey := entityList.Aggregate

	//create data
	expRes := []int64{1, 2, 3, 6}
	testCipherVect := *lib.EncryptIntVector(aggregateKey, expRes)
	expRes1 := []int64{7, 8, 9, 7}
	testCipherVect1 := *lib.EncryptIntVector(aggregateKey, expRes1)
	var tabi []lib.ClientResponse
	tabi = make([]lib.ClientResponse, 2)

	tabi[0] = lib.ClientResponse{GroupingAttributesClear: "", ProbaGroupingAttributesEnc: testCipherVect1, AggregatingAttributes: testCipherVect}
	tabi[1] = lib.ClientResponse{GroupingAttributesClear: "", ProbaGroupingAttributesEnc: testCipherVect, AggregatingAttributes: testCipherVect1}

	clientPrivate := suite.Scalar().Pick(random.Stream)
	clientPublic := suite.Point().Mul(suite.Point().Base(), clientPrivate)

	//protocol
	protocol.TargetOfSwitch = &tabi
	protocol.TargetPublicKey = &clientPublic
	protocol.Proofs = true
	feedback := protocol.FeedbackChannel

	go protocol.Start()

	timeout := network.WaitRetry * time.Duration(network.MaxRetryConnect * 5 * 2) * time.Millisecond

	select {
	case encryptedResult := <-feedback:
		cv1 := encryptedResult[0]
		res := lib.DecryptIntVector(clientPrivate, &cv1.AggregatingAttributes)
		resGrp := lib.DecryptIntVector(clientPrivate, &cv1.ProbaGroupingAttributesEnc)
		log.Lvl1("Recieved results (attributes) ", res)
		log.Lvl1("Recieved results (groups) ", resGrp)
		cv2 := encryptedResult[1]
		res1 := lib.DecryptIntVector(clientPrivate, &cv2.AggregatingAttributes)
		resGrp1 := lib.DecryptIntVector(clientPrivate, &cv2.ProbaGroupingAttributesEnc)
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
