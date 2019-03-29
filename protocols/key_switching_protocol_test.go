package protocolsunlynx_test

import (
	"testing"
	"time"

	"github.com/lca1/unlynx/lib/key_switch"
	"github.com/lca1/unlynx/protocols"
	"go.dedis.ch/kyber/v3"

	"reflect"

	"github.com/lca1/unlynx/lib"
	"go.dedis.ch/kyber/v3/util/random"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
)

func TestCTKS(t *testing.T) {
	local := onet.NewLocalTest(libunlynx.SuiTe)
	_, err := onet.GlobalProtocolRegister("CTKSTest", NewCTKSTest)
	if err != nil {
		log.Fatal("Failed to register the CTKSTest protocol:", err)
	}
	_, entityList, tree := local.GenTree(5, true)

	defer local.CloseAll()

	rootInstance, err := local.CreateProtocol("CTKSTest", tree)
	if err != nil {
		t.Fatal("Couldn't start protocol:", err)
	}

	protocol := rootInstance.(*protocolsunlynx.KeySwitchingProtocol)
	aggregateKey := entityList.Aggregate

	data1 := []int64{1, 2, 3, 6}
	cv1 := *libunlynx.EncryptIntVector(aggregateKey, data1)

	data2 := []int64{7, 8, 9, 7}
	cv2 := *libunlynx.EncryptIntVector(aggregateKey, data2)

	tabi := make(libunlynx.CipherVector, 0)
	tabi = append(tabi, cv1...)
	tabi = append(tabi, cv2...)
	clientPrivate := libunlynx.SuiTe.Scalar().Pick(random.New())
	clientPublic := libunlynx.SuiTe.Point().Mul(clientPrivate, libunlynx.SuiTe.Point().Base())

	//protocol
	protocol.TargetOfSwitch = &tabi
	protocol.TargetPublicKey = &clientPublic
	protocol.Proofs = true
	protocol.ProofFunc = func(pubKey, targetPubKey kyber.Point, secretKey kyber.Scalar, ks2s, rBNegs []kyber.Point, vis []kyber.Scalar) *libunlynxkeyswitch.PublishedKSListProof {
		proof := libunlynxkeyswitch.KeySwitchListProofCreation(pubKey, targetPubKey, secretKey, ks2s, rBNegs, vis)
		return &proof
	}

	feedback := protocol.FeedbackChannel

	go func() {
		if err := protocol.Start(); err != nil {
			log.Fatal("Failed to start Key Switching protocol:", err)
		}
	}()

	timeout := network.WaitRetry * time.Duration(network.MaxRetryConnect*5*2) * time.Millisecond

	select {
	case encryptedResult := <-feedback:
		cv1 := encryptedResult
		res := libunlynx.DecryptIntVector(clientPrivate, &cv1)
		log.Lvl2("Received results (attributes) ", res)

		if !reflect.DeepEqual(res, append(data1, data2...)) {
			t.Fatal("Wrong results, expected", data1, "but got", res)
		} else {
			t.Log("Good results")
		}
	case <-time.After(timeout):
		t.Fatal("Didn't finish in time")
	}
}

// NewCTKSTest is a special purpose protocol constructor specific to tests.
func NewCTKSTest(tni *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	pi, err := protocolsunlynx.NewKeySwitchingProtocol(tni)
	protocol := pi.(*protocolsunlynx.KeySwitchingProtocol)
	protocol.Proofs = true
	protocol.ProofFunc = func(pubKey, targetPubKey kyber.Point, secretKey kyber.Scalar, ks2s, rBNegs []kyber.Point, vis []kyber.Scalar) *libunlynxkeyswitch.PublishedKSListProof {
		proof := libunlynxkeyswitch.KeySwitchListProofCreation(pubKey, targetPubKey, secretKey, ks2s, rBNegs, vis)
		return &proof
	}

	return protocol, err
}
