package protocols

import (
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/network"
	"errors"
	"gopkg.in/dedis/onet.v1/log"
	"math/big"
	"unlynx/prio_utils"

	"github.com/henrycg/prio/utils"

)


const PrioVerificationProtocolName = "PrioVerification"


/*Messages
____________________________________________________________________________________________________________________
 */

//structure to announce start of protocol
type AnnounceVerification struct {}
type ResponseVerification struct {}

//share broadcasted by each client to reconstrut d & e for Beaver MPC
type CorShare struct {
	CorShareD []byte
	CorShareE []byte
}

// Evaluation of each share of the polynomial all send to leader to check if valid
type OutShare struct {
	Out		[]byte
}
/*Structs
_________________________________________________________________________________________________________________________
*/

type StructAnnounce struct {
	*onet.TreeNode
	AnnounceVerification
}


type StructResponse struct {
	*onet.TreeNode
	ResponseVerification
}

type StructCorShare struct {
	*onet.TreeNode
	CorShare
}

type StructOutShare struct {
	*onet.TreeNode
	OutShare
}


type PrioVerificationProtocol struct {
	*onet.TreeNodeInstance

	//the Data to aggregate
	AggregateData chan []*big.Int


	//Channel for waking up all
	AnnounceChannel chan StructAnnounce
	ResponsceChannel chan StructResponse

	//Data structure to perform range proofs
	Request *prio_utils.Request
	Pre     *prio_utils.CheckerPrecomp
	Checker *prio_utils.Checker
	IsOkay   bool

	//channel for proof
	CorShareChannel chan StructCorShare
	OutShareChannel		chan StructOutShare

}


/*
_______________________________________________________________________________
 */
var randomKey = utils.RandomPRGKey()

func init() {
	network.RegisterMessage(AnnounceVerification{})
	network.RegisterMessage(ResponseVerification{})
	network.RegisterMessage(CorShare{})
	onet.GlobalProtocolRegister(PrioVerificationProtocolName,NewPrioVerifcationProtocol)
}


func NewPrioVerifcationProtocol(n *onet.TreeNodeInstance) (onet.ProtocolInstance,error) {

	st := &PrioVerificationProtocol{
		TreeNodeInstance: n,
		AggregateData:         make(chan []*big.Int,1),

	}


	//register the channel for announce
	err := st.RegisterChannel(&st.AnnounceChannel)
	if err != nil {
		return nil, errors.New("couldn't register Announce data channel: " + err.Error())
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
func (p*PrioVerificationProtocol) Start() error {
	p.SendToChildren(&AnnounceVerification{})

	return nil
}
//dispatch is called on the node and handle incoming messages

func (p*PrioVerificationProtocol) Dispatch() error {

	//wakeUp all server
	if(!p.IsRoot()) {
		if (!p.IsLeaf()) {
			p.SendToChildren(&AnnounceVerification{})
		}
	}
	//log.Lvl1("Server p" ,p.Index() ," wait on ")
	p.waitOnSignal()

	//Do the proof, send back the shares to aggregate
	//start := time.Now()
	//log.Lvl1(" Server p ",p.Index() , "start Aggreg")
	datas := p.collectiveVerificationPhase()

	if p.IsRoot() {
		log.Lvl1(datas)
	}
	//log.Lvl1(p.ServerIdentity(), " completed aggregation phase (", sum, " is the sum ) in ", time.Since(start))
	//report result
	return nil
}


//function to avoid broadcasting with server not launched, so wait for everyone to say it is awake
func (p *PrioVerificationProtocol)waitOnSignal() {
	//log.Lvl1("server enter in WaitOnSigal")
	if !p.IsLeaf() {
		//log.Lvl1(p.Index() , " waits to receive response on Resp chnnel")

		j := <- p.ResponsceChannel
		//log.Lvl1("Send to parent" , p.Index())
		//log.Lvl1(j)
		if (!p.IsRoot()) {
			p.SendToParent(&j)
		}

	}
	if !p.IsRoot() {
		//log.Lvl1("Leaf send to parent")
		p.SendToParent(&ResponseVerification{})
	}

}

// Do the validation given a request from a Client, return the share that are supposed to be aggregated by each server
func (p *PrioVerificationProtocol) collectiveVerificationPhase() []*big.Int {


	//SNIP's proof
	log.Lvl1(p.Request)
	log.Lvl1(p.ServerIdentity())
	//each protocol has its checker and it's request ( 1 request per server per client request)
	check := p.Checker
	check.SetReq(p.Request)

	evalReplies := new(prio_utils.CorShare)
	//here evalReplies filled by evaluating on a point ( same for all protocols for a single client )
	evalReplies = check.CorShare(p.Pre)

	//Each proto need to send to each others
	//log.Lvl1("Broadcasting from", p.Index())
	//log.Lvl1("Broadcasting share", evalReplies[0])
	p.Broadcast(&CorShare{evalReplies.ShareD.Bytes(), evalReplies.ShareE.Bytes()})

	//Now they need to all send shares to each other so can all reconstruct cor
	evalRepliesFromAll := make([]*prio_utils.CorShare, 1)
	evalRepliesFromAll[0] = evalReplies

	//for each server get the value broadcasted
	for i := 0; i < p.Tree().Size()-1; i++ {
		v := <-p.CorShareChannel
		corshare := new(prio_utils.CorShare)
		corshare.ShareD = big.NewInt(0).SetBytes(v.CorShareD)
		corshare.ShareE = big.NewInt(0).SetBytes(v.CorShareE)
		evalRepliesFromAll = append(evalRepliesFromAll, corshare)
	}

	//cor is same for all server you cannot be transfered it that's why you transfer the shares
	cor := check.Cor(evalRepliesFromAll)

	//log.Lvl1(p.Index(), " All cor should be the same", cor)
	//we need to do this on all servers as they all have a part of the beaver triple
	finalReplies := make([]*prio_utils.OutShare, 1)

	//random key is same for all, evaluate cor on a randomKey
	finalReplies[0] = check.OutShare(cor, randomKey)


	//send to Root all evaluation
	if !p.IsRoot() {
		p.SendTo(p.Root(), &OutShare{finalReplies[0].Check.Bytes()})
	}


	//then the leader  do all the rest, check if its valid
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
		p.IsOkay = true

	}

	result := make([]*big.Int,len(check.Outputs()))

	for i := 0; i < len(check.Outputs()); i++ {
		result[i] = check.Outputs()[i].WireValue
	}

	p.AggregateData <- result


	return result
}

