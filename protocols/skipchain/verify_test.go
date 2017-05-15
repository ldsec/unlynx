package protocols_test

import (
	"testing"

	"github.com/JoaoAndreSa/MedCo/protocols/skipchain"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/network"
	"time"
	"medblock/service/topology"
	"github.com/dedis/onet/log"
)

// TestVerifyTopology tests verify topology protocol
func TestVerifyTopology(t *testing.T) {
	local := onet.NewLocalTest()
	_, _, tree := local.GenTree(3, true)

	defer local.CloseAll()

	rootInstance, err := local.CreateProtocol("VerifyBlock", tree)
	if err != nil {
		t.Fatal("Couldn't start protocol:", err)
	}
	protocol := rootInstance.(*protocols.VerifyBlockProtocol)


	block := topology.RandomData(1,4,2)
	b,err := network.Marshal(block)
	if err != nil {
		log.Fatal("While marshalling", err)
	}
	feedback := protocol.FeedbackChannel
	protocol.TargetBlock = b

	//run protocol
	go protocol.Start()

	timeout := network.WaitRetry * time.Duration(network.MaxRetryConnect*5*2) * time.Millisecond

	select {
	case verificationList := <-feedback:
		log.LLvl1(verificationList)
	case <-time.After(timeout):
		t.Fatal("Didn't finish in time")
	}

}
