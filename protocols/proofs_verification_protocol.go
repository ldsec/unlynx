// Package protocols contains the proof verification protocol which permits a server
// to Check all available proofs.
// We suppose the existence of a database of all generated proofs and in this protocol, the server running it will
// verify all the proofs.
package protocols

import (
	"github.com/lca1/unlynx/lib"
	"gopkg.in/dedis/onet.v1"
)

// ProofsVerificationProtocolName is the registered name for the proof verification protocol.
const ProofsVerificationProtocolName = "ProofsVerification"

func init() {
	onet.GlobalProtocolRegister(ProofsVerificationProtocolName, NewProofsVerificationProtocol)
}

// Protocol
//______________________________________________________________________________________________________________________

// ProofsToVerify contains all proofs which have to be checked
type ProofsToVerify struct {
	KeySwitchingProofs          []lib.PublishedSwitchKeyProof
	DeterministicTaggingProofs  []lib.PublishedDeterministicTaggingProof
	DetTagAdditionProofs        []lib.PublishedDetTagAdditionProof
	AggregationProofs           []lib.PublishedAggregationProof
	ShufflingProofs             []lib.PublishedShufflingProof
	CollectiveAggregationProofs []lib.PublishedCollectiveAggregationProof
}

// ProofsVerificationProtocol is a struct holding the state of a protocol instance.
type ProofsVerificationProtocol struct {
	*onet.TreeNodeInstance

	// Protocol feedback channel
	FeedbackChannel chan []bool

	// Protocol state data
	TargetOfVerification ProofsToVerify
}

// NewProofsVerificationProtocol is constructor of Proofs Verification protocol instances.
func NewProofsVerificationProtocol(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	pvp := &ProofsVerificationProtocol{
		TreeNodeInstance: n,
		FeedbackChannel:  make(chan []bool),
	}

	return pvp, nil
}

var finalResult = make(chan []bool)

// Start is called at the root to start the execution of the key switching.
func (p *ProofsVerificationProtocol) Start() error {

	nbrKsProofs := len(p.TargetOfVerification.KeySwitchingProofs)
	nbrDtProofs := len(p.TargetOfVerification.DeterministicTaggingProofs)
	nbrDetTagAddProofs := len(p.TargetOfVerification.DetTagAdditionProofs)
	nbrAggrProofs := len(p.TargetOfVerification.AggregationProofs)
	nbrShuffleProofs := len(p.TargetOfVerification.ShufflingProofs)
	nbrCollectiveAggrProofs := len(p.TargetOfVerification.CollectiveAggregationProofs)
	resultSize := nbrKsProofs + nbrAggrProofs + nbrDtProofs + nbrDetTagAddProofs + nbrShuffleProofs + nbrCollectiveAggrProofs

	//log.Lvl1(nbrKsProofs, nbrDtProofs, nbrDetTagAddProofs, nbrAggrProofs, nbrShuffleProofs, nbrCollectiveAggrProofs, resultSize)

	result := make([]bool, resultSize)

	// key switching ***********************************************************************************
	wg := lib.StartParallelize(nbrKsProofs)
	keySwitchTime := lib.StartTimer(p.Name() + "_KeySwitchingVerif")
	for i, v := range p.TargetOfVerification.KeySwitchingProofs {
		if lib.PARALLELIZE {
			go func(i int, v lib.PublishedSwitchKeyProof) {
				result[i] = lib.PublishedSwitchKeyCheckProof(v)
				defer wg.Done()
			}(i, v)
		} else {
			result[i] = lib.PublishedSwitchKeyCheckProof(v)
		}

	}
	lib.EndParallelize(wg)
	lib.EndTimer(keySwitchTime)

	// deterministic tagging ***********************************************************************************
	wg = lib.StartParallelize(nbrDtProofs)
	detTagTime := lib.StartTimer(p.Name() + "_DetTagVerif")
	for i, v := range p.TargetOfVerification.DeterministicTaggingProofs {
		if lib.PARALLELIZE {
			go func(i int, v lib.PublishedDeterministicTaggingProof) {
				result[nbrKsProofs+i], _ = lib.PublishedDeterministicTaggingCheckProof(v)
				defer wg.Done()
			}(i, v)
		} else {
			result[nbrKsProofs+i], _ = lib.PublishedDeterministicTaggingCheckProof(v)
		}
	}

	lib.EndParallelize(wg)
	lib.EndTimer(detTagTime)

	// deterministic tagging 2 ***********************************************************************************
	wg = lib.StartParallelize(nbrDetTagAddProofs)
	detTagAddTime := lib.StartTimer(p.Name() + "_DetTagAddVerif")
	for i, v := range p.TargetOfVerification.DetTagAdditionProofs {
		if lib.PARALLELIZE {
			go func(i int, v lib.PublishedDetTagAdditionProof) {
				result[nbrKsProofs+nbrDtProofs+i] = lib.DetTagAdditionProofVerification(v)
				defer wg.Done()
			}(i, v)
		} else {
			result[nbrKsProofs+nbrDtProofs+i] = lib.DetTagAdditionProofVerification(v)
		}
	}

	lib.EndParallelize(wg)
	lib.EndTimer(detTagAddTime)

	// local aggregation ***********************************************************************************

	wg = lib.StartParallelize(nbrAggrProofs)
	localAggrTime := lib.StartTimer(p.Name() + "_LocalAggrVerif")
	for i, v := range p.TargetOfVerification.AggregationProofs {
		if lib.PARALLELIZE {
			go func(i int, v lib.PublishedAggregationProof) {
				result[nbrKsProofs+nbrDtProofs+nbrDetTagAddProofs+i] = lib.AggregationProofVerification(v)
				defer wg.Done()
			}(i, v)
		} else {
			result[nbrKsProofs+nbrDtProofs+nbrDetTagAddProofs+i] = lib.AggregationProofVerification(v)
		}
	}

	lib.EndParallelize(wg)
	lib.EndTimer(localAggrTime)

	// shuffling ***********************************************************************************
	wg = lib.StartParallelize(nbrShuffleProofs)
	shufflingTime := lib.StartTimer(p.Name() + "_ShufflingVerif")
	for i, v := range p.TargetOfVerification.ShufflingProofs {
		if lib.PARALLELIZE {
			go func(i int, v lib.PublishedShufflingProof) {
				result[nbrKsProofs+nbrDtProofs+nbrDetTagAddProofs+nbrAggrProofs+i] = lib.ShufflingProofVerification(v, p.Roster().Aggregate)
				defer wg.Done()
			}(i, v)
		} else {
			result[nbrKsProofs+nbrDtProofs+nbrDetTagAddProofs+nbrAggrProofs+i] = lib.ShufflingProofVerification(v, p.Roster().Aggregate)

		}
	}

	lib.EndParallelize(wg)
	lib.EndTimer(shufflingTime)

	// collective aggregation ***********************************************************************************
	wg = lib.StartParallelize(nbrCollectiveAggrProofs)
	collAggrTime := lib.StartTimer(p.Name() + "_CollectiveAggrVerif")
	for i, v := range p.TargetOfVerification.CollectiveAggregationProofs {
		if lib.PARALLELIZE {
			go func(i int, v lib.PublishedCollectiveAggregationProof) {
				result[nbrKsProofs+nbrDtProofs+nbrDetTagAddProofs+nbrAggrProofs+nbrShuffleProofs+i] = lib.CollectiveAggregationProofVerification(v)
				defer wg.Done()
			}(i, v)
		} else {
			result[nbrKsProofs+nbrDtProofs+nbrDetTagAddProofs+nbrAggrProofs+nbrShuffleProofs+i] = lib.CollectiveAggregationProofVerification(v)

		}
	}

	lib.EndParallelize(wg)
	lib.EndTimer(collAggrTime)

	finalResult <- result
	return nil
}

// Dispatch is called on each node. It waits for incoming messages and handle them.
func (p *ProofsVerificationProtocol) Dispatch() error {
	aux := <-finalResult
	p.FeedbackChannel <- aux
	return nil
}
