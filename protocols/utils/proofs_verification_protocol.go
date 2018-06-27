// Package protocolsunlynxutils contains the proof verification protocol which permits a server
// to check all available proofs.
// We suppose the existence of a database of all generated proofs and in this protocol, the server running it will
// verify all the proofs.
package protocolsunlynxutils

import (
	"github.com/dedis/onet"
	"github.com/lca1/unlynx/lib"
	"github.com/lca1/unlynx/lib/proofs"
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
	KeySwitchingProofs          []libunlynxproofs.PublishedSwitchKeyProof
	DeterministicTaggingProofs  []libunlynxproofs.PublishedDeterministicTaggingProof
	DetTagAdditionProofs        []libunlynxproofs.PublishedDetTagAdditionProof
	AggregationProofs           []libunlynxproofs.PublishedAggregationProof
	ShufflingProofs             []libunlynxproofs.PublishedShufflingProof
	CollectiveAggregationProofs []libunlynxproofs.PublishedCollectiveAggregationProof
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
	wg := libunlynx.StartParallelize(nbrKsProofs)
	keySwitchTime := libunlynx.StartTimer(p.Name() + "_KeySwitchingVerif")
	for i, v := range p.TargetOfVerification.KeySwitchingProofs {
		if libunlynx.PARALLELIZE {
			go func(i int, v libunlynxproofs.PublishedSwitchKeyProof) {
				result[i] = libunlynxproofs.PublishedSwitchKeyCheckProof(v)
				defer wg.Done()
			}(i, v)
		} else {
			result[i] = libunlynxproofs.PublishedSwitchKeyCheckProof(v)
		}

	}
	libunlynx.EndParallelize(wg)
	libunlynx.EndTimer(keySwitchTime)

	// deterministic tagging ***********************************************************************************
	wg = libunlynx.StartParallelize(nbrDtProofs)
	detTagTime := libunlynx.StartTimer(p.Name() + "_DetTagVerif")
	for i, v := range p.TargetOfVerification.DeterministicTaggingProofs {
		if libunlynx.PARALLELIZE {
			go func(i int, v libunlynxproofs.PublishedDeterministicTaggingProof) {
				result[nbrKsProofs+i], _ = libunlynxproofs.PublishedDeterministicTaggingCheckProof(v)
				defer wg.Done()
			}(i, v)
		} else {
			result[nbrKsProofs+i], _ = libunlynxproofs.PublishedDeterministicTaggingCheckProof(v)
		}
	}

	libunlynx.EndParallelize(wg)
	libunlynx.EndTimer(detTagTime)

	// deterministic tagging 2 ***********************************************************************************
	wg = libunlynx.StartParallelize(nbrDetTagAddProofs)
	detTagAddTime := libunlynx.StartTimer(p.Name() + "_DetTagAddVerif")
	for i, v := range p.TargetOfVerification.DetTagAdditionProofs {
		if libunlynx.PARALLELIZE {
			go func(i int, v libunlynxproofs.PublishedDetTagAdditionProof) {
				result[nbrKsProofs+nbrDtProofs+i] = libunlynxproofs.DetTagAdditionProofVerification(v)
				defer wg.Done()
			}(i, v)
		} else {
			result[nbrKsProofs+nbrDtProofs+i] = libunlynxproofs.DetTagAdditionProofVerification(v)
		}
	}

	libunlynx.EndParallelize(wg)
	libunlynx.EndTimer(detTagAddTime)

	// local aggregation ***********************************************************************************

	wg = libunlynx.StartParallelize(nbrAggrProofs)
	localAggrTime := libunlynx.StartTimer(p.Name() + "_LocalAggrVerif")
	for i, v := range p.TargetOfVerification.AggregationProofs {
		if libunlynx.PARALLELIZE {
			go func(i int, v libunlynxproofs.PublishedAggregationProof) {
				result[nbrKsProofs+nbrDtProofs+nbrDetTagAddProofs+i] = libunlynxproofs.AggregationProofVerification(v)
				defer wg.Done()
			}(i, v)
		} else {
			result[nbrKsProofs+nbrDtProofs+nbrDetTagAddProofs+i] = libunlynxproofs.AggregationProofVerification(v)
		}
	}

	libunlynx.EndParallelize(wg)
	libunlynx.EndTimer(localAggrTime)

	// shuffling ***********************************************************************************
	wg = libunlynx.StartParallelize(nbrShuffleProofs)
	shufflingTime := libunlynx.StartTimer(p.Name() + "_ShufflingVerif")
	for i, v := range p.TargetOfVerification.ShufflingProofs {
		if libunlynx.PARALLELIZE {
			go func(i int, v libunlynxproofs.PublishedShufflingProof) {
				result[nbrKsProofs+nbrDtProofs+nbrDetTagAddProofs+nbrAggrProofs+i] = libunlynxproofs.ShufflingProofVerification(v, p.Roster().Aggregate)
				defer wg.Done()
			}(i, v)
		} else {
			result[nbrKsProofs+nbrDtProofs+nbrDetTagAddProofs+nbrAggrProofs+i] = libunlynxproofs.ShufflingProofVerification(v, p.Roster().Aggregate)

		}
	}

	libunlynx.EndParallelize(wg)
	libunlynx.EndTimer(shufflingTime)

	// collective aggregation ***********************************************************************************
	wg = libunlynx.StartParallelize(nbrCollectiveAggrProofs)
	collAggrTime := libunlynx.StartTimer(p.Name() + "_CollectiveAggrVerif")
	for i, v := range p.TargetOfVerification.CollectiveAggregationProofs {
		if libunlynx.PARALLELIZE {
			go func(i int, v libunlynxproofs.PublishedCollectiveAggregationProof) {
				result[nbrKsProofs+nbrDtProofs+nbrDetTagAddProofs+nbrAggrProofs+nbrShuffleProofs+i] = libunlynxproofs.CollectiveAggregationProofVerification(v)
				defer wg.Done()
			}(i, v)
		} else {
			result[nbrKsProofs+nbrDtProofs+nbrDetTagAddProofs+nbrAggrProofs+nbrShuffleProofs+i] = libunlynxproofs.CollectiveAggregationProofVerification(v)

		}
	}

	libunlynx.EndParallelize(wg)
	libunlynx.EndTimer(collAggrTime)

	finalResult <- result
	return nil
}

// Dispatch is called on each node. It waits for incoming messages and handle them.
func (p *ProofsVerificationProtocol) Dispatch() error {
	defer p.Done()

	aux := <-finalResult
	p.FeedbackChannel <- aux
	return nil
}
