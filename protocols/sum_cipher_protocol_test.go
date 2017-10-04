package protocols

import (
	"testing"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/network"
	"time"
	"github.com/stretchr/testify/assert"
	"math/big"
)

func TestSumCipherProtocol(t *testing.T) {

	local := onet.NewLocalTest()

	// You must register this protocol before creating the servers
	onet.GlobalProtocolRegister("SumCipherTest",NewSumCipherTest)
	_, _, tree := local.GenTree(10, true)
	defer local.CloseAll()

	p, err := local.CreateProtocol("SumCipherTest", tree)
	if err != nil {
		t.Fatal("Couldn't start protocol:", err)
	}

	protocol := p.(*ProtocolSumCipher)

	go protocol.Start()
	timeout := network.WaitRetry * time.Duration(network.MaxRetryConnect*5*2) * time.Millisecond


	//verify results

	expectedResults := big.NewInt(int64(5))

	select {
	case Result := <- protocol.Feedback:
		assert.Equal(t, *expectedResults, *Result)
	case <-time.After(timeout):
		t.Fatal("Didn't finish in time")
	}
}

//inject Test data
func NewSumCipherTest(tni *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	pi, err := NewSumCipherProtocol(tni)
	protocol := pi.(*ProtocolSumCipher)

	testCiphers := make([]*big.Int,10)

	switch tni.Index() {
	case 0:
		testCiphers[0] = big.NewInt(int64(1))
	case 1:
		testCiphers[1] = big.NewInt(int64(1))
	case 2:
		testCiphers[2] = big.NewInt(int64(1))
	case 9:
		testCiphers[9] = big.NewInt(int64(1))
	case 5:
		testCiphers[5] = big.NewInt(int64(1))
	default:
	}
	protocol.Ciphers = testCiphers

	return protocol, err
}