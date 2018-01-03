package protocols

import (
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/network"
	"errors"

	"math/big"

	"gopkg.in/dedis/onet.v1/log"
)

/**
This is a simple protocol that collect and aggregate by notifying the tree structure until
leaf are reached. Then they locally aggregate the sahre they have and send to the parent.
The root recolt all the data and publish the final aggregations
 */

const PrioAggregationProtocolName = "PrioAggregation"



/*_________________________________________________________________________________________________________________
*/

//structure to announce start of protocol
//Reply from the children
type ReplySumCipherBytes struct {
	Bytes []byte
}

type AnnounceAggregation struct {}



/*
_________________________________________________________________________________________________________________________
*/

//Structure containing reply of node
type StructReply struct {
	*onet.TreeNode
	ReplySumCipherBytes
}

//Structure containing announce of node
type StructAnnounceAggregation struct {
	*onet.TreeNode
	AnnounceAggregation
}

//Basic structure representing the protocol, the Feedback channel contains the
//result of the aggregation
type PrioAggregationProtocol struct {
	*onet.TreeNodeInstance

	//the feedback final
	Feedback chan *big.Int

	//Channel for up and down communication respectively
	ChildDataChannel chan []StructReply
	AnnounceChannel chan StructAnnounceAggregation

	//The data of the protocol : shares from server, local sum and Modulus
	Shares  []*big.Int
	Sum 	*big.Int
	Modulus *big.Int


}

//Tell which message are gonna be used in the protocol
func init() {
	network.RegisterMessage(AnnounceAggregation{})
	network.RegisterMessage(ReplySumCipherBytes{})
	onet.GlobalProtocolRegister(PrioAggregationProtocolName,NewPrioAggregationProtocol)
}


func NewPrioAggregationProtocol(n *onet.TreeNodeInstance) (onet.ProtocolInstance,error) {
	//initialize the local sum to 0 and channel
	st := &PrioAggregationProtocol{
		TreeNodeInstance: n,
		Feedback:         make(chan *big.Int),
		Sum:              big.NewInt(int64(0)),
	}

	//register the channel for announce
	err := st.RegisterChannel(&st.AnnounceChannel)
	if err != nil {
		return nil, errors.New("couldn't register Announce data channel: " + err.Error())
	}

	//register the channel for child response
	err = st.RegisterChannel(&st.ChildDataChannel)
	if err != nil {
		return nil, errors.New("couldn't register Child Response channel" + err.Error())
	}

	return st,nil
}

//start called at the root
func (p*PrioAggregationProtocol) Start() error {
	// log.Lvl1(p.ServerIdentity(), " started a Sum Cipher Protocol (", len(p.Request), " different shares)")


	p.SendToChildren(&AnnounceAggregation{})
	//start := time.Now()
	//log.Lvl1("time to send mesage to children of root ", time.Since(start))
	return nil
}

//dispatch is called on the node and handle incoming messages
func (p*PrioAggregationProtocol) Dispatch() error {

	//send if you're not the root (done in start), and only if you have children
	if(!p.IsRoot()) {
		if (!p.IsLeaf()) {
			p.SendToChildren(&AnnounceAggregation{})
		}
	}
	//log.Lvl1("Server p" ,p.Index() ," wait on ")
	//p.waitOnSignal()

	//Ascending aggreg
	//start := time.Now()
	//log.Lvl1(" Server p ",p.Index() , "start Aggreg")
	sum := p.ascendingAggregationPhase()
	//log.Lvl1(p.ServerIdentity(), " completed aggregation phase (", sum, " is the sum ) in ", time.Since(start))

	//report result
	if p.IsRoot() {
		p.Feedback <-sum
	}
	return nil
}


// Results pushing up the tree containing aggregation results.
func (p *PrioAggregationProtocol) ascendingAggregationPhase() *big.Int {


	if !p.IsLeaf() {
		//wait on the channel for child to complete and add sum
		//take time only at the root
		for _, v := range <-p.ChildDataChannel {
			//get the bytes and turn them back in big.Int
			var sum big.Int
			sum.SetBytes(v.Bytes)
			p.Sum.Add(p.Sum, &sum)
			p.Sum.Mod(p.Sum, p.Modulus)
		}
	}

	//do the sum of ciphers
	log.Lvl1(p.Shares)
	for i := 0; i < len(p.Shares); i++ {
		p.Sum.Add(p.Sum, p.Shares[i])
		p.Sum.Mod(p.Sum, p.Modulus)
	}

	//send to parent the sum to deblock channel wait
	if !p.IsRoot() {
		//send the big.Int in bytes
		p.SendToParent(&ReplySumCipherBytes{p.Sum.Bytes()})
		p.Sum = big.NewInt(0)
	}

	//finish by returning the sum of the root
	p.Sum.Mod(p.Sum, p.Modulus)

	return p.Sum

}

