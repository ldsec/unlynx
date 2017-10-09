package protocols

import (
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/network"
	"errors"
	"gopkg.in/dedis/onet.v1/log"
	"math/big"
	"unlynx/utils"
	"math"
)


const SumCipherProtocolName = "SumCipher"


/*Messages
____________________________________________________________________________________________________________________
 */

 //structure to announce start of protocol
type AnnounceSumCipher struct {
}

//Reply from the children
type ReplySumCipherBytes struct {
	Bytes []byte
}

type ReplySumCipherLength struct {
	BigIntLen int
	BitLen int
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
	ReplySumCipherBytes
}

type StructLength struct{
	*onet.TreeNode
	ReplySumCipherLength
}

type Cipher struct {
	Share *big.Int

	//for the moment put bit in int
	Bits []uint
}

type ProtocolSumCipher struct {
	*onet.TreeNodeInstance

	//the feedback final
	Feedback chan *big.Int

	//Channel for up and down communication
	ChildDataChannel chan []StructReply
	LengthDataChannel chan []StructLength

	AnnounceChannel chan StructAnnounce

	//The data of the protocol
	Ciphers []Cipher
	Sum 	*big.Int
	Modulus *big.Int
}
/*
_______________________________________________________________________________
 */

func init() {
	network.RegisterMessage(AnnounceSumCipher{})
	network.RegisterMessage(ReplySumCipherBytes{})
	network.RegisterMessage(ReplySumCipherLength{})
	onet.GlobalProtocolRegister(SumCipherProtocolName,NewSumCipherProtocol)
}


func NewSumCipherProtocol(n *onet.TreeNodeInstance) (onet.ProtocolInstance,error) {
	st := &ProtocolSumCipher{
		TreeNodeInstance: n,
		Feedback: make(chan *big.Int),
		Sum: big.NewInt(int64(0)),
	}

	err := st.RegisterChannel(&st.AnnounceChannel)
	if err != nil {
		return nil, errors.New("couldn't register Announce data channel: " + err.Error())
	}

	err = st.RegisterChannel(&st.ChildDataChannel)
	if err != nil {
		return nil, errors.New("couldn't register Child Response channel" + err.Error())
	}

	err = st.RegisterChannel(&st.LengthDataChannel)
	if err != nil {
		return nil, errors.New("couldn't register Length channel" + err.Error())
	}

	return st,nil
}

//start called at the root
func (p* ProtocolSumCipher) Start() error {
	if p.Ciphers == nil {
			return errors.New("No Shares to collect")
	}
	log.Lvl1(p.ServerIdentity(), " started a Sum Cipher Protocol (", len(p.Ciphers), " different shares)")

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
	log.Lvl1(p.ServerIdentity(), " completed aggregation phase (", sum, " is the sum )")

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
func (p *ProtocolSumCipher) ascendingAggregationPhase() *big.Int {

	if p.Ciphers == nil {
		p.Sum = big.NewInt(0)
	}

	if !p.IsLeaf() {
		//wait on the channel for child to complete and add sum
		for _, v := range <-p.ChildDataChannel {
			//get the bytes and turn them back in big.Int
			var sum big.Int
			sum.SetBytes(v.Bytes)
			p.Sum.Add(p.Sum, &sum)
			p.Sum.Mod(p.Sum,p.Modulus)
		}
	}

	//do the sum of ciphers
	for _, v := range p.Ciphers {
		if !Verify(v) {
			log.Lvl1("Share refused")
		}
		p.Sum.Add(p.Sum, v.Share)
		p.Sum.Mod(p.Sum,p.Modulus)
	}

	//send to parent the sum to deblock channel wait
	if !p.IsRoot() {
		//send the big.Int in bytes
		p.SendToParent(&ReplySumCipherBytes{p.Sum.Bytes()})
	}

	//finish by returning the sum of the root
	p.Sum.Mod(p.Sum,p.Modulus)
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
		out[i] = utils.RandInt(mod)

		acc.Add(acc, out[i])
	}

	acc.Sub(secret, acc)
	acc.Mod(acc, mod)
	out[nPieces-1] = acc

	return out
}


func Encode(x *big.Int) (Cipher) {
	length := x.BitLen()
	resultBit := make([]uint,length)
	for i := 0; i < length; i++ {
		resultBit[i] = x.Bit(i)
	}
	cipher := Cipher{x,resultBit}
	return cipher
}

func Verify(c Cipher) (bool) {
	verify := 0.0
	length := 0.0
	for _,b := range c.Bits {
		if b>1 || b<0 {
			errors.New("Not bits form in the encoding")
			return false
		}
		verify+= math.Pow(2,length)*float64(b)
		length++
	}
	difference := big.NewInt(int64(0))
	difference.Sub(c.Share,big.NewInt(int64(verify)))
	if difference.Uint64()== uint64(0) {
		return true
	}
	errors.New(" The share is not equal to it's bit form")
	return false
}

func Decode(c Cipher)(x *big.Int) {
	return c.Share
}