package protocols

import (
	"testing"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/network"
	"time"
	"github.com/stretchr/testify/assert"
	"math/big"
	"math"
	"gopkg.in/dedis/onet.v1/log"
)
//the field cardinality must be superior to nbclient*2^b where b is the maximum number of bit a client need to encode its value

var field = big.NewInt(int64(math.Pow(2.0,32)))
var nbClient = 3
var nbServ = 10

var serv1Secret = big.NewInt(int64(156165846161468691))
var serv2Secret = big.NewInt(int64(5484156416846153))
var serv3Secret = big.NewInt(int64(568465186461844))

var serv1Share = Share(field,nbServ,serv1Secret)
var serv2Share = Share(field,nbServ,serv2Secret)
var serv3Share = Share(field,nbServ,serv3Secret)

func TestSumCipherProtocol(t *testing.T) {

	local := onet.NewLocalTest()

	// You must register this protocol before creating the servers
	onet.GlobalProtocolRegister("SumCipherTest",NewSumCipherTest)
	_, _, tree := local.GenTree(nbServ, true)
	defer local.CloseAll()

	p, err := local.CreateProtocol("SumCipherTest", tree)
	if err != nil {
		t.Fatal("Couldn't start protocol:", err)
	}

	protocol := p.(*ProtocolSumCipher)

	start := time.Now()
	go protocol.Start()
	timeout := network.WaitRetry * time.Duration(network.MaxRetryConnect*5*2) * time.Millisecond


	//verify results
	expectedResults := big.NewInt(int64(0))


	expectedResults.Add(expectedResults,serv1Secret)
	expectedResults.Add(expectedResults,serv2Secret)
	expectedResults.Add(expectedResults,serv3Secret)
	expectedResults.Mod(expectedResults,field)


	select {
	case Result := <- protocol.Feedback:
		log.Lvl1("time elapsed is ",time.Since(start))
		assert.Equal(t, expectedResults, Result)
	case <-time.After(timeout):
		t.Fatal("Didn't finish in time")
	}
}

//inject Test data
func NewSumCipherTest(tni *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	pi, err := NewSumCipherProtocol(tni)
	protocol := pi.(*ProtocolSumCipher)


	testCiphers := make([]*big.Int,nbClient)

	//assign the shares to each server
	testCiphers[0] = serv1Share[tni.Index()]
	testCiphers[1] = serv2Share[tni.Index()]
	testCiphers[2] = serv3Share[tni.Index()]

	protocol.Ciphers = testCiphers
	protocol.Modulus = field
	return protocol, err
}