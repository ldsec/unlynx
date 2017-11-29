package protocols

import (
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/network"
	"errors"

	"math/big"

)


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

type StructReply struct {
	*onet.TreeNode
	ReplySumCipherBytes
}


type StructAnnounceAggregation struct {
	*onet.TreeNode
	AnnounceAggregation
}


type PrioAggregationProtocol struct {
	*onet.TreeNodeInstance

	//the feedback final
	Feedback chan *big.Int

	//Channel for up and down communication
	ChildDataChannel chan []StructReply

	AnnounceChannel chan StructAnnounceAggregation

	//The data of the protocol
	Shares  []*big.Int
	Sum 	*big.Int
	Modulus *big.Int


}


func init() {
	network.RegisterMessage(AnnounceAggregation{})
	network.RegisterMessage(ReplySumCipherBytes{})
	onet.GlobalProtocolRegister(PrioAggregationProtocolName,NewPrioAggregationProtocol)
}


func NewPrioAggregationProtocol(n *onet.TreeNodeInstance) (onet.ProtocolInstance,error) {

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

