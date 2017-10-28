package protocols

import (
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/network"
	"errors"
	"gopkg.in/dedis/onet.v1/log"
	"math/big"
	"time"

	"unlynx/prio_utils"

	"github.com/henrycg/prio/utils"
	"github.com/henrycg/prio/share"
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

type CorShare struct {
	CorShare *prio_utils.CorShare
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

type StructCorShare struct {
	*onet.TreeNode
	CorShare
}

type Cipher struct {
	Share *big.Int

	//for the moment put bit in int
	Bits []uint
}


type AcceptReply struct {
}

type SumCipherProtocol struct {
	*onet.TreeNodeInstance

	//the feedback final
	Feedback chan *big.Int

	//Channel for up and down communication
	ChildDataChannel chan []StructReply

	AnnounceChannel chan StructAnnounce

	//The data of the protocol
	Ciphers []Cipher
	Sum 	*big.Int
	Modulus *big.Int

	//for proofs
	Proofs  bool
	Request []*prio_utils.Request
	pre		[]*prio_utils.CheckerPrecomp
	Checker	*prio_utils.Checker

	//channel for proof
	CorShareChannel	chan []StructCorShare

}



type StatusFlag int

// Status of a client submission.
const (
	NotStarted    StatusFlag = iota
	OpenedTriples StatusFlag = iota
	Layer1        StatusFlag = iota
	Finished      StatusFlag = iota
)

type RequestStatus struct {
	check *prio_utils.Checker
	flag  StatusFlag
}
/*
_______________________________________________________________________________
 */

func init() {
	network.RegisterMessage(AnnounceSumCipher{})
	network.RegisterMessage(ReplySumCipherBytes{})
	network.RegisterMessage(CorShare{})
	onet.GlobalProtocolRegister(SumCipherProtocolName,NewSumCipherProtocol)
}


func NewSumCipherProtocol(n *onet.TreeNodeInstance) (onet.ProtocolInstance,error) {

	st := &SumCipherProtocol{
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

	err = st.RegisterChannel(&st.CorShareChannel)
	if err != nil {
		return nil, errors.New("Couldn't register CorrShare channer" + err.Error())
	}

	return st,nil
}

//start called at the root
func (p*SumCipherProtocol) Start() error {
	if p.Ciphers == nil {
			return errors.New("No Shares to collect")
	}
	log.Lvl1(p.ServerIdentity(), " started a Sum Cipher Protocol (", len(p.Ciphers), " different shares)")

	start := time.Now()
	//send to the children of the root
	p.SendToChildren(&AnnounceSumCipher{})
	log.Lvl1("time to send mesage to children of root ", time.Since(start))
	return nil
	}
//dispatch is called on the node and handle incoming messages

func (p*SumCipherProtocol) Dispatch() error {

	//Go down the tree
	if !p.IsRoot() {
		p.sumCipherAnnouncementPhase()
	}

	//Ascending aggreg
	start := time.Now()
	sum := p.ascendingAggregationPhase()
	log.Lvl1(p.ServerIdentity(), " completed aggregation phase (", sum, " is the sum ) in ", time.Since(start))

	//report result
	if p.IsRoot() {
		p.Feedback <-sum
	}
	return nil
}

func (p *SumCipherProtocol) sumCipherAnnouncementPhase() {
	//send down the tree if you have some
	AnnounceMessage := <-p.AnnounceChannel
	if !p.IsLeaf() {
		p.SendToChildren(&AnnounceMessage.AnnounceSumCipher)
	}
}

// Results pushing up the tree containing aggregation results.
func (p *SumCipherProtocol) ascendingAggregationPhase() *big.Int {


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
			log.Lvl1("Share refused, will not use it for the operation ")
		} else {
			p.Sum.Add(p.Sum, Decode(v))
			p.Sum.Mod(p.Sum, p.Modulus)
		}
	}

	//send to parent the sum to deblock channel wait
	if !p.IsRoot() {
		//send the big.Int in bytes
		p.SendToParent(&ReplySumCipherBytes{p.Sum.Bytes()})
	}

	//finish by returning the sum of the root
	p.Sum.Mod(p.Sum,p.Modulus)


	if (p.Proofs) {
		status := new(RequestStatus)
		status.check = p.Checker
		status.check.SetReq(p.Request[p.Index()])

		log.Lvl1(p.Tree().Size())

		evalReplies := make([]*prio_utils.CorShare, 1)
		//need to do this for all shares so for all servers

		p.pre[p.Index()].SetCheckerPrecomp(utils.RandInt(share.IntModulus))

		//here evalReplies filled
		evalReplies[0] = status.check.CorShare(p.pre[p.Index()])

		//From here need to wait all evalReplies
		if !p.IsRoot() {
			p.SendTo(p.Root(), &CorShare{evalReplies[0]})
		}

		if p.IsRoot() {
			evalRepliesFromAll := make([]*prio_utils.CorShare,1)
			evalRepliesFromAll[0] = evalReplies[0]
			/*for _, v := range <-p.CorShareChannel {
				evalRepliesFromAll = append(evalRepliesFromAll, v.CorShare.CorShare )
			}*/
			cor := status.check.Cor(evalRepliesFromAll)
			finalReplies := make([]*prio_utils.OutShare, 1)
			finalReplies[p.Index()] = status.check.OutShare(cor, utils.RandomPRGKey())
			log.Lvl1(finalReplies)
			log.Lvl1("outpus is valide is ", status.check.OutputIsValid(finalReplies))
		}
	}
	return p.Sum

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
	verify := big.NewInt(0)
	for i,b := range c.Bits {
		if b>1 || b<0 {
			panic("Not bits form in the encoding")
			return false
		}
		verify.Add(verify,big.NewInt(0).Mul(big.NewInt(int64(b)),big.NewInt(0).Exp(big.NewInt(2),big.NewInt(int64(i)),nil)))

	}
	difference := big.NewInt(int64(0))
	difference.Sub(c.Share,verify)
	if difference.Uint64()== uint64(0) {
		return true
	}
	errors.New(" The share is not equal to it's bit form")
	return false
}

func Decode(c Cipher)(x *big.Int) {
	return c.Share
}

