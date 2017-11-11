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
var nbClient = 2
var nbServ = 5

//3 random number to test
var serv1Secret = big.NewInt(int64(55189642165))
var serv2Secret = big.NewInt(int64(4515416566156))
var serv3Secret = big.NewInt(int64(2486186416513))

//the share of them
var serv1Share = prio_utils.Share(field,nbServ,serv1Secret)
var serv2Share = prio_utils.Share(field,nbServ,serv2Secret)
var serv3Share = prio_utils.Share(field,nbServ,serv3Secret)



var req = prio_utils.ClientRequest(serv1Share, 0)
var req2 = prio_utils.ClientRequest(serv2Share, 0)
var randomPoint = utils.RandInt(share.IntModulus)
var randomPoint2 = utils.RandInt(share.IntModulus)

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
	expectedResults.Add(expectedResults,serv2Secret)
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


	protocol.Proofs = true

	ckt := prio_utils.ConfigToCircuit(serv1Share)
	ckt2 := prio_utils.ConfigToCircuit(serv2Share)
	protocol.Modulus = field
	protocol.Request = make([]*prio_utils.Request,nbClient)
	protocol.Request[0] = req[tni.Index()]
	protocol.Request[1] = req2[tni.Index()]

	protocol.Checker = make([]*prio_utils.Checker,nbClient)
	protocol.Checker[0] = prio_utils.NewChecker(ckt,protocol.Index(),0)
	protocol.Checker[1] = prio_utils.NewChecker(ckt2,protocol.Index(),0)

	protocol.pre = make([]*prio_utils.CheckerPrecomp,nbClient)

	protocol.pre[0] = prio_utils.NewCheckerPrecomp(ckt)
	protocol.pre[0].SetCheckerPrecomp(randomPoint)

	protocol.pre[1] = prio_utils.NewCheckerPrecomp(ckt2)
	protocol.pre[1].SetCheckerPrecomp(randomPoint2)


	return protocol, err
}