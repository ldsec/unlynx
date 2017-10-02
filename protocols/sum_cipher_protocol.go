package protocols

import (
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/network"
	"errors"
	"gopkg.in/dedis/onet.v1/log"
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

	Feedback chan int

	ChildDataChannel     chan []StructReply
	AnnounceChannel chan StructAnnounce

	Ciphers []int
	Sum 	int
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
		Feedback: make(chan int),
	}

	err := st.RegisterChannel(&st.AnnounceChannel)
	if err != nil {
		return nil, errors.New("couldn't register data reference channel: " + err.Error())
	}

	err = st.RegisterChannel(&st.ChildDataChannel)
	if err != nil {
		return nil, errors.New("couldn't register child reference channel" + err.Error())
	}

	return st,nil
}

//start called at the root
func (p* ProtocolSumCipher) Start() error {
	if p.Ciphers == nil {
			return errors.New("No Shares to collect")
	}
	log.Lvl1(p.ServerIdentity(), " started a Sum Cipher Protocol (", len(p.Ciphers), "local group(s) )")
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

	sum := p.ascendingAggregationPhase()
	log.Lvl1(p.ServerIdentity(), " completed aggregation phase (", sum, " is the sum ")

	//report result
	if p.IsRoot() {
		p.Feedback <-sum
	}
	return nil
}

func (p *ProtocolSumCipher) sumCipherAnnouncementPhase() {
	AnnounceMessage := <-p.AnnounceChannel
	if !p.IsLeaf() {
		p.SendToChildren(&AnnounceMessage.AnnounceSumCipher)
	}
}

// Results pushing up the tree containing aggregation results.
func (p *ProtocolSumCipher) ascendingAggregationPhase() int {

	if p.Ciphers == nil {
		p.Sum = 0
	}

	if !p.IsLeaf() {

		for _, v := range <-p.ChildDataChannel {
			p.Sum += v.Sum
		}
	}

	for _, v := range p.Ciphers {
			p.Sum += v
	}

	if !p.IsRoot() {
		log.Lvl1("The sum is ",p.Sum)
		p.SendToParent(&ReplySumCipher{p.Sum})

	}

	return p.Sum
}






