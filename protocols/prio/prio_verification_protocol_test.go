package prio

import (
	"testing"
	"gopkg.in/dedis/onet.v1"
	"time"
//	"math/big"

	"gopkg.in/dedis/onet.v1/log"
	"unlynx/lib/prio_utils"
	"github.com/henrycg/prio/share"
	"github.com/henrycg/prio/utils"
	"github.com/stretchr/testify/assert"
	"github.com/henrycg/prio/config"
)
//the field cardinality must be superior to nbclient*2^b where b is the maximum number of bit a client need to encode its value

var field = share.IntModulus

var nbServ = 2

//3 random number to test
//var serv1Secret = big.NewInt(int64(55))

//the share of them
//var serv1Share = prio_utils.Share(field,nbServ,serv1Secret)


//var req = prio_utils.ClientRequest(serv1Share, 0)
//var datas = []*config.Field{&config.Field{Name:"test",Type:config.FieldType(byte(5)),LinRegBits:[]int{14,7,1,2,7,8,1,3,8,1,8,4,4,1}},&config.Field{Name:"Test2",Type:config.FieldType(byte(5)),LinRegBits:[]int{1,2,5,2,7,3,8,1,8,1,8,3,6,12}}}
var datas = []*config.Field{&config.Field{Name:"Int1",Type:config.FieldType(byte(0)),IntBits:2}}
var req = prio_utils.ClientRequest(datas, nbServ,0)
var randomPoint = utils.RandInt(share.IntModulus)


func TestPrioVerificationProtocol(t *testing.T) {

	local := onet.NewLocalTest()

	// You must register this protocol before creating the servers
	onet.GlobalProtocolRegister("PrioVerificationTest", NewPrioVerificationTest)
	_, _, tree := local.GenTree(nbServ, true)
	defer local.CloseAll()

	p, err := local.CreateProtocol("PrioVerificationTest", tree)
	if err != nil {
		t.Fatal("Couldn't start protocol:", err)
	}

	protocol := p.(*PrioVerificationProtocol)

	start := time.Now()
	protocol.Start()

	//timeout := network.WaitRetry * time.Duration(network.MaxRetryConnect*5*2) * time.Millisecond
	if (protocol.IsRoot()) {
		Result :=  <-protocol.AggregateData
		log.Lvl1("time elapsed is ", time.Since(start))
		assert.NotZero(t,len(Result))
	}


}

//inject Test data
func NewPrioVerificationTest(tni *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	pi, err := NewPrioVerifcationProtocol(tni)
	protocol := pi.(*PrioVerificationProtocol)

	//set circuit
	ckt := prio_utils.ConfigToCircuit(datas)

	//set request, checker and preChecker
	protocol.Request = new(prio_utils.Request)
	protocol.Request = req[tni.Index()]


	protocol.Checker = new(prio_utils.Checker)
	protocol.Checker = prio_utils.NewChecker(ckt,protocol.Index(),0)

	protocol.Pre = new(prio_utils.CheckerPrecomp)

	protocol.Pre = prio_utils.NewCheckerPrecomp(ckt)
	protocol.Pre.SetCheckerPrecomp(randomPoint)


	return protocol, err
}