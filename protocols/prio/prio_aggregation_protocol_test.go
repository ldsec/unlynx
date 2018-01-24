package prio

import (
	"testing"
	"gopkg.in/dedis/onet.v1"
	"time"

	"gopkg.in/dedis/onet.v1/log"

	"math/big"
	"unlynx/lib/prio_utils"
	"github.com/henrycg/prio/share"
	"github.com/stretchr/testify/assert"
	"gopkg.in/dedis/onet.v1/network"

)
//the field cardinality must be superior to nbclient*2^b
// where b is the maximum number of bit a client need to encode its value


var nbS = 5

//2 random number to test, you can test it with smaller number to see the sum yourself
var secret1 = big.NewInt(int64(55189642165))
var secret2= big.NewInt(int64(5518495792165))


//the share of them
var secret1Share = prio_utils.Share(share.IntModulus,nbS,secret1)
var secret2Share = prio_utils.Share(share.IntModulus,nbS,secret2)

func TestPrioAggregationProtocol(t *testing.T) {

	local := onet.NewLocalTest()

	// You must register this protocol before creating the servers
	onet.GlobalProtocolRegister("PrioAggregationTest", NewPrioAggregationTest)
	_, _, tree := local.GenTree(nbS, true)
	defer local.CloseAll()

	p, err := local.CreateProtocol("PrioAggregationTest", tree)
	if err != nil {
		t.Fatal("Couldn't start protocol:", err)
	}

	protocol := p.(*PrioAggregationProtocol)

	start := time.Now()
	protocol.Start()
	timeout := network.WaitRetry * time.Duration(network.MaxRetryConnect*5*2) * time.Millisecond

	//verify results
	expectedResults := big.NewInt(int64(0))


	expectedResults.Add(expectedResults,secret1)
	expectedResults.Add(expectedResults,secret2)
	expectedResults.Mod(expectedResults,field)


	select {
	case Result := <- protocol.Feedback:
		log.Lvl1("time elapsed is ",time.Since(start))
		assert.Equal(t, expectedResults, Result[0])
	case <-time.After(timeout):
		t.Fatal("Didn't finish in time")
	}


}

//inject Test data
func NewPrioAggregationTest(tni *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {

	pi, err := NewPrioAggregationProtocol(tni)
	protocol := pi.(*PrioAggregationProtocol)

	//here assign a share of each secret to the server.
	// Meaning if 2 server, secret1 = [share1,share2] each of them goes to different server
	// (1 and 2 respectively even if order does not matter)
	//You use AFE encoding to encode the shares.

	protocol.Modulus = share.IntModulus
	protocol.Shares = make([][]*big.Int,0)
	protocol.Shares = append(protocol.Shares,Encode(secret1Share[tni.Index()]))
	protocol.Shares = append(protocol.Shares,Encode(secret2Share[tni.Index()]))

	return protocol, err
}


//Encoding of simple Sum AFE
func Encode(x *big.Int)([]*big.Int) {
	result := make([]*big.Int,1)
	result[0] = x
	for j:= 0 ;j < x.BitLen() ; j++ {
		result = append(result,big.NewInt(int64(x.Bit(j))))
	}
	for (len(result)<64) {
		result = append(result,big.NewInt(0))
	}
	return result
}

