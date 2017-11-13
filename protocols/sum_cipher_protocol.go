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

)


const SumCipherProtocolName = "SumCipher"


/*Messages
____________________________________________________________________________________________________________________
 */

//structure to announce start of protocol
type AnnounceSumCipher struct {
}
type ResponseSumCipher struct {

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
	CorShareD []byte
	CorShareE []byte
}

type OutShare struct {
	Out		[]byte
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

type StructResponse struct {
	*onet.TreeNode
	ResponseSumCipher
}

type StructCorShare struct {
	*onet.TreeNode
	CorShare
}

type StructOutShare struct {
	*onet.TreeNode
	OutShare
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
	ResponsceChannel chan StructResponse
	//The data of the protocol
	Sum 	*big.Int
	Modulus *big.Int

	//for proofs
	Proofs  bool
	Request []*prio_utils.Request
	Pre     []*prio_utils.CheckerPrecomp
	Checker []*prio_utils.Checker
	Leader  bool
	//channel for proof
	CorShareChannel	chan StructCorShare
	OutShareChannel		chan StructOutShare

}





/*
_______________________________________________________________________________
 */
var randomKey = utils.RandomPRGKey()

func init() {
	network.RegisterMessage(AnnounceSumCipher{})
	network.RegisterMessage(ReplySumCipherBytes{})
	network.RegisterMessage(ResponseSumCipher{})
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
		return nil, errors.New("Couldn't register CorrShare channel" + err.Error())
	}

	err = st.RegisterChannel(&st.OutShareChannel)
	if err !=nil {
		return nil,errors.New("Couldn't register OutShare channel" + err.Error())
	}

	err = st.RegisterChannel(&st.ResponsceChannel)
	if err !=nil {
		return nil,errors.New("Couldn't register response wake up channel" + err.Error())
	}

	return st,nil
}

//start called at the root
func (p*SumCipherProtocol) Start() error {
	log.Lvl1(p.ServerIdentity(), " started a Sum Cipher Protocol (", len(p.Request), " different shares)")


	p.SendToChildren(&AnnounceSumCipher{})
	start := time.Now()
	log.Lvl1("time to send mesage to children of root ", time.Since(start))
	return nil
}
//dispatch is called on the node and handle incoming messages

func (p*SumCipherProtocol) Dispatch() error {

	if(!p.IsRoot()) {
		if (!p.IsLeaf()) {
			p.SendToChildren(&AnnounceSumCipher{})
		}
	}
	//log.Lvl1("Server p" ,p.Index() ," wait on ")
	p.waitOnSignal()

	//Ascending aggreg
	start := time.Now()
	log.Lvl1(" Server p ",p.Index() , "start Aggreg")
	sum := p.ascendingAggregationPhase()
	log.Lvl1(p.ServerIdentity(), " completed aggregation phase (", sum, " is the sum ) in ", time.Since(start))

	//report result
	if p.IsRoot() {
		p.Feedback <-sum
	}
	return nil
}


func (p *SumCipherProtocol)waitOnSignal() {
	//log.Lvl1("server enter in WaitOnSigal")
	if !p.IsLeaf() {
		//log.Lvl1(p.Index() , " waits to receive response on Resp chnnel")

		j := <- p.ResponsceChannel
		//log.Lvl1("Send to parent" , p.Index())
		log.Lvl1(j)
		if (!p.IsRoot()) {
			p.SendToParent(&j)
		}

	}
	if !p.IsRoot() {
		//log.Lvl1("Leaf send to parent")
		p.SendToParent(&ResponseSumCipher{})
	}

}

// Results pushing up the tree containing aggregation results.
func (p *SumCipherProtocol) ascendingAggregationPhase() *big.Int {


	//SNIP's proof
	if (p.Proofs) {
		for i := 0; i < len(p.Request); i++ {

			//find solution for this
			count := 0
			for(count < 100000000) {
				count++
			}

			//each protocol has its checker and it's request ( 1 request per server per client request)
			check := p.Checker[i]
			check.SetReq(p.Request[i])

			evalReplies := make([]*prio_utils.CorShare, 1)
			//here evalReplies filled by evaluating on a point ( same for all protocols for a single client )
			evalReplies[0] = check.CorShare(p.Pre[i])

			//Each proto need to send to each others
			//log.Lvl1("Broadcasting from", p.Index())
			//log.Lvl1("Broadcasting share", evalReplies[0])
			p.Broadcast(&CorShare{evalReplies[0].ShareD.Bytes(), evalReplies[0].ShareE.Bytes()})

			//Now they need to all send shares to each other so can all reconstruct cor
			evalRepliesFromAll := make([]*prio_utils.CorShare, 1)
			evalRepliesFromAll[0] = evalReplies[0]

			//for each server get the value broadcasted
			for i := 0; i < p.Tree().Size()-1; i++ {
				v := <-p.CorShareChannel
				corshare := new(prio_utils.CorShare)
				corshare.ShareD = big.NewInt(0).SetBytes(v.CorShareD)
				corshare.ShareE = big.NewInt(0).SetBytes(v.CorShareE)
				evalRepliesFromAll = append(evalRepliesFromAll, corshare)
			}

			//cor is same for all server you cannot transfer it that's why you transfer the shares
			cor := check.Cor(evalRepliesFromAll)

			log.Lvl1(p.ServerIdentity(), " All cor should be the same",cor)
			//we need to do this on all servers as they all have a part of the beaver triple
			finalReplies := make([]*prio_utils.OutShare, 1)

			//random key is same for all
			finalReplies[0] = check.OutShare(cor, randomKey)


			if !p.IsRoot() {
				p.SendTo(p.Root(), &OutShare{finalReplies[0].Check.Bytes()})
			}

			//then the leader  do all the rest
			if p.IsRoot() {
				finalRepliesAll := make([]*prio_utils.OutShare, 1)
				finalRepliesAll[0] = finalReplies[0]
				for i := 0; i < p.Tree().Size()-1; i++ {
					v := <-p.OutShareChannel
					outShare := new(prio_utils.OutShare)
					outShare.Check = big.NewInt(0).SetBytes(v.OutShare.Out)
					finalRepliesAll = append(finalRepliesAll, outShare)
				}


				isValid := check.OutputIsValid(finalRepliesAll)
				log.Lvl1("output is valid ? ", isValid)
				if (!isValid) {
					panic("Proof is NOT VALID")
				}
			}

			if !p.IsLeaf() {
				//wait on the channel for child to complete and add sum
				for _, v := range <-p.ChildDataChannel {
					//get the bytes and turn them back in big.Int
					var sum big.Int
					sum.SetBytes(v.Bytes)
					p.Sum.Add(p.Sum, &sum)
					p.Sum.Mod(p.Sum, p.Modulus)
				}
			}

			//do the sum of ciphers

			for i := 0; i < len(check.Outputs()); i++ {
				p.Sum.Add(p.Sum, check.Outputs()[i].WireValue)
				p.Sum.Mod(p.Sum, p.Modulus)
			}

			//send to parent the sum to deblock channel wait
			if !p.IsRoot() {
				//send the big.Int in bytes
				p.SendToParent(&ReplySumCipherBytes{p.Sum.Bytes()})
				p.Sum = big.NewInt(0)
			}
		}

		//finish by returning the sum of the root
		p.Sum.Mod(p.Sum, p.Modulus)
	}

	return p.Sum

}

