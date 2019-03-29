// Package protocolsunlynxutils contains the proof verification protocol which permits a server
// to check all available proofs.
// We suppose the existence of a database of all generated proofs and in this protocol, the server running it will
// verify all the proofs.
package protocolsunlynxutils

import (
	"github.com/lca1/unlynx/lib"
	"github.com/lca1/unlynx/lib/aggregation"
	"github.com/lca1/unlynx/lib/deterministic_tag"
	"github.com/lca1/unlynx/lib/key_switch"
	"github.com/lca1/unlynx/lib/shuffle"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
)

// ProofsVerificationProtocolName is the registered name for the proof verification protocol.
const ProofsVerificationProtocolName = "ProofsVerification"

func init() {
	if _, err := onet.GlobalProtocolRegister(ProofsVerificationProtocolName, NewProofsVerificationProtocol); err != nil {
		log.Fatal("Error registering <LocalAggregationProtocol>:", err)
	}
}

// Protocol
//______________________________________________________________________________________________________________________

// ProofsToVerify contains all proofs which have to be checked
type ProofsToVerify struct {
	KeySwitchingProofs          libunlynxkeyswitch.PublishedKSListProof
	DetTagCreationProofs        libunlynxdetertag.PublishedDDTCreationListProof
	DetTagAdditionProofs        libunlynxdetertag.PublishedDDTAdditionListProof
	AggregationProofs           libunlynxaggr.PublishedAggregationListProof
	ShufflingProofs             libunlynxshuffle.PublishedShufflingListProof
	CollectiveAggregationProofs libunlynxaggr.PublishedAggregationListProof
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

	// we have 6 different types of proofs (check ProofsToVerify struct)
	result := make([]bool, 6)

	// key switching ***************************************************************************************************
	keySwitchTime := libunlynx.StartTimer(p.Name() + "_KeySwitchingVerif")
	result[0] = libunlynxkeyswitch.KeySwitchListProofVerification(p.TargetOfVerification.KeySwitchingProofs, 1.0)
	libunlynx.EndTimer(keySwitchTime)

	// deterministic tagging (creation) ********************************************************************************
	detTagTime := libunlynx.StartTimer(p.Name() + "_DetTagVerif")
	result[1] = libunlynxdetertag.DeterministicTagCrListProofVerification(p.TargetOfVerification.DetTagCreationProofs, 1.0)
	libunlynx.EndTimer(detTagTime)

	// deterministic tagging (addition) ********************************************************************************

	detTagAddTime := libunlynx.StartTimer(p.Name() + "_DetTagAddVerif")
	result[2] = libunlynxdetertag.DeterministicTagAdditionListProofVerification(p.TargetOfVerification.DetTagAdditionProofs, 1.0)
	libunlynx.EndTimer(detTagAddTime)

	// local aggregation ***********************************************************************************************

	localAggrTime := libunlynx.StartTimer(p.Name() + "_LocalAggrVerif")
	result[3] = libunlynxaggr.AggregationListProofVerification(p.TargetOfVerification.AggregationProofs, 1.0)
	libunlynx.EndTimer(localAggrTime)

	// shuffling *******************************************************************************************************

	shufflingTime := libunlynx.StartTimer(p.Name() + "_ShufflingVerif")
	result[4] = libunlynxshuffle.ShuffleListProofVerification(p.TargetOfVerification.ShufflingProofs, p.Roster().Aggregate, 1.0)
	libunlynx.EndTimer(shufflingTime)

	// collective aggregation ******************************************************************************************

	collectiveAggrTime := libunlynx.StartTimer(p.Name() + "_CollectiveAggrVerif")
	result[5] = libunlynxaggr.AggregationListProofVerification(p.TargetOfVerification.CollectiveAggregationProofs, 1.0)
	libunlynx.EndTimer(collectiveAggrTime)

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
