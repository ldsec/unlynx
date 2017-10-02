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

	Sum chan int
	Ciphers []int

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
		Sum : make(chan int),
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

/*
func (p *ProtocolSumCipher) HandleAnnounce(announce StructAnnounce) error{
	if !p.IsLeaf() {
		p.SendToChildren(&announce.AnnounceSumCipher)
	} else {
		p.HandleReply(nil)
	}
	return nil

}

func (p *ProtocolSumCipher) HandleReply(reply []StructReply) error {
	defer p.Done()

	sum := 0
	for _, c := range reply {
		sum += c.Sum
	}
	log.Lvl3(p.ServerIdentity().Address, "is done with total of", sum)
	if !p.IsRoot() {
		log.Lvl3("Sending to parent")
		return p.SendTo(p.Parent(), &ReplySumCipher{sum})
	}
	log.Lvl3("Root-node is done - nbr of children found:", sum)
	p.Sum <- sum
	return nil
}
*/
//dispatch is called on the node and handle incoming messages
func (p* ProtocolSumCipher) Dispatch() error {

	//Go down the tree
	if !p.IsRoot() {
		p.sumCipherAnnouncementPhase()
	}
	//Ascending aggreg
	p.ascendingAggregationPhase()
	log.Lvl1(p.ServerIdentity(), " completed aggregation phase (", len(p.Ciphers), "group(s) )")

	//report result

	return nil
}

func (p *ProtocolSumCipher) sumCipherAnnouncementPhase() {
	if !p.IsLeaf() {
		p.SendToChildren(&AnnounceSumCipher{})
	}
}

// Results pushing up the tree containing aggregation results.
func (p *ProtocolSumCipher) ascendingAggregationPhase() error {

	if p.Ciphers == nil {
		p.Sum <- 0
	}

	sum := 0
	for _,v  := range p.Ciphers{
		log.Lvl1(v,p.ServerIdentity())
		sum+= v


	}
	log.Lvl3(p.ServerIdentity().Address, "is done with total of", sum)
	if !p.IsRoot() {
		p.SendTo(p.Parent(),&ReplySumCipher{sum})
	}

	p.Sum <-sum


	return nil
}






