package protocols

import (
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/network"
	"errors"
)


const SumCipherProtocolName = "SumCipher"


/*Messages
____________________________________________________________________________________________________________________
 */

 //structure to announce start of protocol
type AnnounceSumCipher struct {
}

type ReplySumCipher struct {
	Sum int
}

type ReplySumCipherBytes struct {
	Bytes []byte
}
/*Structs
_________________________________________________________________________________________________________________________
*/



type StructAnnounce struct {
	*onet.TreeNode
	AnnounceSumCipher
}


type StructReply struct {
	*onet.TreeNode
	ReplySumCipher
}

type ProtocolSumCipher struct {

	*onet.TreeNodeInstance
	Message string
	Ciphers []int
	Sum chan int

}
/*
_______________________________________________________________________________
 */
func init() {
	network.RegisterMessage(AnnounceSumCipher{})
	network.RegisterMessage(ReplySumCipher{})
	onet.GlobalProtocolRegister(SumCipherProtocolName,NewSumCipherProtocol)
}


func NewSumCipherProtocol(n *onet.TreeNodeInstance) (onet.ProtocolInstance,error) {
	st := &ProtocolSumCipher{
		TreeNodeInstance: n,
		Sum: 			make(chan int),
	}
	return st,nil
}

//start called at the root
func (p* ProtocolSumCipher) Start() error {
	if p.Ciphers == nil {
			return errors.New("No Shares to collect")
		}
	//send to the children of the root
	p.SendToChildren(&AnnounceSumCipher{})

	return nil
	}

//dispatch is called on the node and handle incoming messages
func (p* ProtocolSumCipher) Dispatch() error {

	//Go down the tree
	if !p.IsRoot() {
		p.sumCipherAnnouncementPhase()
	}

	//Ascending aggreg
	aggregateSum := p.ascendingAggregationPhase()

	//report result
	if p.IsRoot() {
		p.Sum <- aggregateSum
	}
	return nil
}

func (p *ProtocolSumCipher) sumCipherAnnouncementPhase() {
	if !p.IsLeaf() {
		p.SendToChildren(&p.Ciphers)
	}
}

// Results pushing up the tree containing aggregation results.
func (p *ProtocolSumCipher) ascendingAggregationPhase() int {

	if p.Ciphers == nil {
		p.Sum  <-0
	}

	//roundTotComput := lib.StartTimer(p.Name() + "_CollectiveAggregation(ascendingAggregation)")

	if !p.IsLeaf() {

		for i, _ := range p.Ciphers {
			childrenContribution := ReplySumCipher{}
			childrenContribution.Sum += p.Ciphers[i]
			//lib.EndTimer(roundProofs)
			//roundComput := lib.StartTimer(p.Name() + "_CollectiveAggregation(Aggregation)")
		}
	}

	//lib.EndTimer(roundTotComput)

	if !p.IsRoot() {

		p.SendToParent(ReplySumCipher{<-p.Sum})

	}

	return <-p.Sum
}





