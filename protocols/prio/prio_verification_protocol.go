package prio

import (
	"errors"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/dedis/onet.v1/network"
	"math/big"
	"unlynx/lib/prioUtils"

	"github.com/henrycg/prio/utils"
)

/**
This protocol is used to verify that a Prio request from a Client is Valid.
At the end it output an array of integer for each protocol ( it is not shared) that represent the share
tha can be used to calculate the final aggregation.
At the beginning we had a request represented by PRG hints and shares of the MPC triple. This is an optimization
done by the Prio creator to send PRG key linked to hash instead of big int directly.
The protocol collectivelly verify if the circuit is Valid (which is available to anyone), on the share inputs.

Note: You cannot check that the output aggregate back to the result needed as you need the data from all
protocol (not only root), but this can be done in the Services/prio. You can be conviced that if the protocol
return True, the protocol has verify correctly and data were correct.
*/

//PrioVerificationProtocolName is the name for Prio's Verification
const PrioVerificationProtocolName = "PrioVerification"

/*Messages
____________________________________________________________________________________________________________________
*/

//AnnounceVerification is the structure to announce start of protocol/
type AnnounceVerification struct{}

//ResponseVerification is the structure to notify that server is awake.
type ResponseVerification struct{}

//CorShare is the share broadcasted by each client to reconstrut d & e for Beaver MPC
type CorShare struct {
	CorShareD []byte
	CorShareE []byte
}

//OutShare is the evaluation of each share of the polynomial all send to leader to check if valid
type OutShare struct {
	Out []byte
}

/*Structs
_________________________________________________________________________________________________________________________
*/

//StructAnnounce announces the protocol
type StructAnnounce struct {
	*onet.TreeNode
	AnnounceVerification
}

//StructResponse is the reply from node to say they are ready to go (to avoid strarting without some server as there is a broadcast)
type StructResponse struct {
	*onet.TreeNode
	ResponseVerification
}

//StructCorShare is the share exchanged by server to reconstruct the d & e MPC.
type StructCorShare struct {
	*onet.TreeNode
	CorShare
}

//StructOutShare is the evaluation of server
type StructOutShare struct {
	*onet.TreeNode
	OutShare
}

//PrioVerificationProtocol is the protocol structure
type PrioVerificationProtocol struct {
	*onet.TreeNodeInstance

	//the Data to aggregate
	AggregateData chan []*big.Int

	//Channel for waking up all
	AnnounceChannel  chan StructAnnounce
	ResponsceChannel chan StructResponse

	//Data structure to perform range proofs
	Request *prioUtils.Request
	Pre     *prioUtils.CheckerPrecomp
	Checker *prioUtils.Checker

	//channel for proof
	CorShareChannel chan StructCorShare
	OutShareChannel chan StructOutShare
}

/*
_______________________________________________________________________________
*/

var randomKey = utils.RandomPRGKey()

func init() {
	network.RegisterMessage(AnnounceVerification{})
	network.RegisterMessage(ResponseVerification{})
	network.RegisterMessage(CorShare{})
	onet.GlobalProtocolRegister(PrioVerificationProtocolName, NewPrioVerifcationProtocol)
}

//NewPrioVerifcationProtocol creates a new Protocol to verify
func NewPrioVerifcationProtocol(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {

	st := &PrioVerificationProtocol{
		TreeNodeInstance: n,
		AggregateData:    make(chan []*big.Int, 1),
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
	if err != nil {
		return nil, errors.New("Couldn't register OutShare channel" + err.Error())
	}

	err = st.RegisterChannel(&st.ResponsceChannel)
	if err != nil {
		return nil, errors.New("Couldn't register response wake up channel" + err.Error())
	}

	return st, nil
}

//Start called at the root
func (p *PrioVerificationProtocol) Start() error {
	p.SendToChildren(&AnnounceVerification{})

	return nil
}

//Dispatch is called on the node and handle incoming messages
func (p *PrioVerificationProtocol) Dispatch() error {

	//wakeUp all server
	if !p.IsRoot() {
		if !p.IsLeaf() {
			p.SendToChildren(&AnnounceVerification{})
		}
	}
	//log.Lvl1("Server p" ,p.Index() ," wait on ")
	p.waitOnSignal()

	//Do the proof, send back the shares to aggregate
	//start := time.Now()
	//log.Lvl1(" Server p ",p.Index() , "start Aggreg")
	p.AggregateData <- p.collectiveVerificationPhase()

	//log.Lvl1(p.ServerIdentity(), " completed aggregation phase (", sum, " is the sum ) in ", time.Since(start))
	//report result
	return nil
}

//function to avoid broadcasting with server not launched, so wait for everyone to say it is awake
func (p *PrioVerificationProtocol) waitOnSignal() {
	//log.Lvl1("server enter in WaitOnSigal")
	if !p.IsLeaf() {
		//log.Lvl1(p.Index() , " waits to receive response on Resp chnnel")

		j := <-p.ResponsceChannel
		//log.Lvl1("Send to parent" , p.Index())
		//log.Lvl1(j)
		if !p.IsRoot() {
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
	//log.Lvl1(p.Request)
	//log.Lvl1(p.ServerIdentity())
	//each protocol has its checker and it's request ( 1 request per server per client request)
	check := p.Checker
	check.SetReq(p.Request)

	evalReplies := new(prioUtils.CorShare)
	//here evalReplies filled by evaluating on a point ( same for all protocols for a single client )
	evalReplies = check.CorShare(p.Pre)

	//Each proto need to send to each others their share to reconstruct the D & E
	//log.Lvl1("Broadcasting from", p.Index())
	//log.Lvl1("Broadcasting share", evalReplies)
	p.Broadcast(&CorShare{evalReplies.ShareD.Bytes(), evalReplies.ShareE.Bytes()})

	//Now they need to reconstruct it
	evalRepliesFromAll := make([]*prioUtils.CorShare, 1)
	evalRepliesFromAll[0] = evalReplies

	//for each server get the value broadcasted
	for i := 0; i < p.Tree().Size()-1; i++ {
		v := <-p.CorShareChannel
		corshare := new(prioUtils.CorShare)
		corshare.ShareD = big.NewInt(0).SetBytes(v.CorShareD)
		corshare.ShareE = big.NewInt(0).SetBytes(v.CorShareE)
		evalRepliesFromAll = append(evalRepliesFromAll, corshare)
	}

	//cor is same for all server and cannot be transfered it that's why you transfer the shares
	cor := check.Cor(evalRepliesFromAll)

	//log.Lvl1(p.Index(), " All cor should be the same", cor)
	//
	// log.Lvl1(p.IsRoot())
	//we need to do this on all servers as they all have a part of the beaver triple
	finalReplies := make([]*prioUtils.OutShare, 1)

	//random key is same for all, evaluate cor on a randomKey
	finalReplies[0] = check.OutShare(cor, randomKey)

	//send to Root all evaluation
	if !p.IsRoot() {
		p.SendTo(p.Root(), &OutShare{finalReplies[0].Check.Bytes()})
	}

	//then the leader  do all the rest, check if its valid
	if p.IsRoot() {
		finalRepliesAll := make([]*prioUtils.OutShare, 1)
		finalRepliesAll[0] = finalReplies[0]
		for i := 0; i < p.Tree().Size()-1; i++ {
			v := <-p.OutShareChannel
			outShare := new(prioUtils.OutShare)
			outShare.Check = big.NewInt(0).SetBytes(v.OutShare.Out)
			finalRepliesAll = append(finalRepliesAll, outShare)
		}
		isValid := check.OutputIsValid(finalRepliesAll)
		log.Lvl1("output is valid ? ", isValid)
		if !isValid {
			return make([]*big.Int, 0)
		}

	}

	result := make([]*big.Int, len(check.Outputs()))

	//This are the actual shares you will need to aggregate
	for i := 0; i < len(check.Outputs()); i++ {
		result[i] = check.Outputs()[i].WireValue
	}

	return result
}
