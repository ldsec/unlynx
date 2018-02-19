// Package protocolsUnLynx contains the proof verification protocol which permits a server
// to check all available proofs.
// We suppose the existence of a database of all generated proofs and in this protocol, the server running it will
// verify all the proofs.
package protocolsUnLynx

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
	KeySwitchingProofs          []libUnLynx.PublishedSwitchKeyProof
	DeterministicTaggingProofs  []libUnLynx.PublishedDeterministicTaggingProof
	DetTagAdditionProofs        []libUnLynx.PublishedDetTagAdditionProof
	AggregationProofs           []libUnLynx.PublishedAggregationProof
	ShufflingProofs             []libUnLynx.PublishedShufflingProof
	CollectiveAggregationProofs []libUnLynx.PublishedCollectiveAggregationProof
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
	wg := libUnLynx.StartParallelize(nbrKsProofs)
	keySwitchTime := libUnLynx.StartTimer(p.Name() + "_KeySwitchingVerif")
	for i, v := range p.TargetOfVerification.KeySwitchingProofs {
		if libUnLynx.PARALLELIZE {
			go func(i int, v libUnLynx.PublishedSwitchKeyProof) {
				result[i] = libUnLynx.PublishedSwitchKeyCheckProof(v)
				defer wg.Done()
			}(i, v)
		} else {
			result[i] = libUnLynx.PublishedSwitchKeyCheckProof(v)
		}

	}
	libUnLynx.EndParallelize(wg)
	libUnLynx.EndTimer(keySwitchTime)

	// deterministic tagging ***********************************************************************************
	wg = libUnLynx.StartParallelize(nbrDtProofs)
	detTagTime := libUnLynx.StartTimer(p.Name() + "_DetTagVerif")
	for i, v := range p.TargetOfVerification.DeterministicTaggingProofs {
		if libUnLynx.PARALLELIZE {
			go func(i int, v libUnLynx.PublishedDeterministicTaggingProof) {
				result[nbrKsProofs+i], _ = libUnLynx.PublishedDeterministicTaggingCheckProof(v)
				defer wg.Done()
			}(i, v)
		} else {
			result[nbrKsProofs+i], _ = libUnLynx.PublishedDeterministicTaggingCheckProof(v)
		}
	}

	libUnLynx.EndParallelize(wg)
	libUnLynx.EndTimer(detTagTime)

	// deterministic tagging 2 ***********************************************************************************
	wg = libUnLynx.StartParallelize(nbrDetTagAddProofs)
	detTagAddTime := libUnLynx.StartTimer(p.Name() + "_DetTagAddVerif")
	for i, v := range p.TargetOfVerification.DetTagAdditionProofs {
		if libUnLynx.PARALLELIZE {
			go func(i int, v libUnLynx.PublishedDetTagAdditionProof) {
				result[nbrKsProofs+nbrDtProofs+i] = libUnLynx.DetTagAdditionProofVerification(v)
				defer wg.Done()
			}(i, v)
		} else {
			result[nbrKsProofs+nbrDtProofs+i] = libUnLynx.DetTagAdditionProofVerification(v)
		}
	}

	libUnLynx.EndParallelize(wg)
	libUnLynx.EndTimer(detTagAddTime)

	// local aggregation ***********************************************************************************

	wg = libUnLynx.StartParallelize(nbrAggrProofs)
	localAggrTime := libUnLynx.StartTimer(p.Name() + "_LocalAggrVerif")
	for i, v := range p.TargetOfVerification.AggregationProofs {
		if libUnLynx.PARALLELIZE {
			go func(i int, v libUnLynx.PublishedAggregationProof) {
				result[nbrKsProofs+nbrDtProofs+nbrDetTagAddProofs+i] = libUnLynx.AggregationProofVerification(v)
				defer wg.Done()
			}(i, v)
		} else {
			result[nbrKsProofs+nbrDtProofs+nbrDetTagAddProofs+i] = libUnLynx.AggregationProofVerification(v)
		}
	}

	libUnLynx.EndParallelize(wg)
	libUnLynx.EndTimer(localAggrTime)

	// shuffling ***********************************************************************************
	wg = libUnLynx.StartParallelize(nbrShuffleProofs)
	shufflingTime := libUnLynx.StartTimer(p.Name() + "_ShufflingVerif")
	for i, v := range p.TargetOfVerification.ShufflingProofs {
		if libUnLynx.PARALLELIZE {
			go func(i int, v libUnLynx.PublishedShufflingProof) {
				result[nbrKsProofs+nbrDtProofs+nbrDetTagAddProofs+nbrAggrProofs+i] = libUnLynx.ShufflingProofVerification(v, p.Roster().Aggregate)
				defer wg.Done()
			}(i, v)
		} else {
			result[nbrKsProofs+nbrDtProofs+nbrDetTagAddProofs+nbrAggrProofs+i] = libUnLynx.ShufflingProofVerification(v, p.Roster().Aggregate)

		}
	}

	libUnLynx.EndParallelize(wg)
	libUnLynx.EndTimer(shufflingTime)

	// collective aggregation ***********************************************************************************
	wg = libUnLynx.StartParallelize(nbrCollectiveAggrProofs)
	collAggrTime := libUnLynx.StartTimer(p.Name() + "_CollectiveAggrVerif")
	for i, v := range p.TargetOfVerification.CollectiveAggregationProofs {
		if libUnLynx.PARALLELIZE {
			go func(i int, v libUnLynx.PublishedCollectiveAggregationProof) {
				result[nbrKsProofs+nbrDtProofs+nbrDetTagAddProofs+nbrAggrProofs+nbrShuffleProofs+i] = libUnLynx.CollectiveAggregationProofVerification(v)
				defer wg.Done()
			}(i, v)
		} else {
			result[nbrKsProofs+nbrDtProofs+nbrDetTagAddProofs+nbrAggrProofs+nbrShuffleProofs+i] = libUnLynx.CollectiveAggregationProofVerification(v)

		}
	}

	libUnLynx.EndParallelize(wg)
	libUnLynx.EndTimer(collAggrTime)

	finalResult <- result
	return nil
}

// Dispatch is called on each node. It waits for incoming messages and handle them.
func (p *ProofsVerificationProtocol) Dispatch() error {
	aux := <-finalResult
	p.FeedbackChannel <- aux
	return nil
}
