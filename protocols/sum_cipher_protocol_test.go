package protocols

import (
	"testing"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/network"
	"time"
	"github.com/stretchr/testify/assert"
	"math/big"

	"gopkg.in/dedis/onet.v1/log"
	"unlynx/prio_utils"
	"github.com/henrycg/prio/share"
	"github.com/henrycg/prio/utils"
)
//the field cardinality must be superior to nbclient*2^b where b is the maximum number of bit a client need to encode its value

var field = share.IntModulus
var nbClient = 1
var nbServ = 1
var randomPoint = utils.RandInt(share.IntModulus)
var req,ckt = prio_utils.ClientRequest(serv1Share, 0)

//3 random number to test
var serv1Secret = big.NewInt(int64(1))
var serv2Secret = big.NewInt(int64(2))
var serv3Secret = big.NewInt(int64(2))

//the share of them
var serv1Share = prio_utils.Share(field,nbServ,serv1Secret)
var serv2Share = prio_utils.Share(field,nbServ,serv2Secret)
var serv3Share = prio_utils.Share(field,nbServ,serv3Secret)

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

	protocol := p.(*SumCipherProtocol)

	start := time.Now()
	go protocol.Start()
	timeout := network.WaitRetry * time.Duration(network.MaxRetryConnect*5*2) * time.Millisecond


	//verify results
	expectedResults := big.NewInt(int64(0))


	expectedResults.Add(expectedResults,serv1Secret)
	//expectedResults.Add(expectedResults,serv2Secret)
	//expectedResults.Add(expectedResults,serv3Secret)
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
	protocol := pi.(*SumCipherProtocol)

	//assign struct of cipher to each server
	encoded := make([]Cipher,nbClient)
	encoded[0] = Encode(serv1Share[tni.Index()])
	//encoded[1] = Encode(serv2Share[tni.Index()])
	//encoded[2] = Encode(serv3Share[tni.Index()])

	protocol.Ciphers = encoded
	//protocol.Modulus = field
	protocol.Proofs = true

	//req length = nb server

	log.Lvl1(serv1Share)

	protocol.Request = req
	//ckt = prio_utils.configToCircuit(dataShared)
	protocol.Checker = prio_utils.NewChecker(ckt,tni.Index(),0)
	protocol.Modulus = ckt.Modulus()
	log.Lvl1("Checker is ", protocol.Checker)


	protocol.pre = prio_utils.NewCheckerPrecomp(ckt)
	protocol.pre.SetCheckerPrecomp(randomPoint)

	return protocol, err
}