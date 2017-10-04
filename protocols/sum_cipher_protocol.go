package protocols

import (
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/network"
	"errors"
	"gopkg.in/dedis/onet.v1/log"
	"math/big"
	"math/rand"
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

	//the feedback final
	Feedback chan int

	//Channel for up and down communication
	ChildDataChannel chan []StructReply
	AnnounceChannel chan StructAnnounce

	//The data of the protocol
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
		return nil, errors.New("couldn't register Announce data channel: " + err.Error())
	}

	err = st.RegisterChannel(&st.ChildDataChannel)
	if err != nil {
		return nil, errors.New("couldn't register Child Response channel" + err.Error())
	}

	return st,nil
}

//start called at the root
func (p* ProtocolSumCipher) Start() error {
	if p.Ciphers == nil {
			return errors.New("No Shares to collect")
	}
	log.Lvl1(p.ServerIdentity(), " started a Sum Cipher Protocol (", len(p.Ciphers), " different shares")

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
	//send down the tree if you have some
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
		//wait on the channel for child to complete and add sum
		for _, v := range <-p.ChildDataChannel {
			p.Sum += v.Sum
		}
	}

	//do the sum of ciphers
	for _, v := range p.Ciphers {
			p.Sum += v
	}

	//send to parent the sum to deblock channel wait
	if !p.IsRoot() {
		p.SendToParent(&ReplySumCipher{p.Sum})
	}

	//finish by returning the sum of the root
	return p.Sum
}


func Share(mod *big.Int, nPieces int, secret *big.Int) []*big.Int {
	if nPieces == 0 {
		panic("Number of shares must be at least 1")
	} else if nPieces == 1 {
		return []*big.Int{secret}
	}
	out := make([]*big.Int, nPieces)

	acc := new(big.Int)
	for i := 0; i < nPieces-1; i++ {
		big,err := GenerateRandomBytes(mod.BitLen())
		if(err ==nil) {
			errors.New("Error while splitting value")
		}
		out[i] = &big

		acc.Add(acc, out[i])
	}
	acc.Sub(secret, acc)
	acc.Mod(acc, mod)
	out[nPieces-1] = acc

	return out
}

func GenerateRandomBytes(n int) (big.Int, error) {
	b := make([]byte, n)
	var result big.Int
	_, err := rand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		return result, err
	}

	result.SetBytes(b)
	return result, nil
}