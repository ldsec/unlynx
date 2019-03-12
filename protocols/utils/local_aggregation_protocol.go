// Package protocolsunlynxutils contains LocalAggregationProtocol and its only purpose is to simulate aggregations done locally
// For example, it can be used to simulate a data provider doing some pre-processing on its data
package protocolsunlynxutils

import (
	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
	"github.com/lca1/unlynx/lib"
	"github.com/lca1/unlynx/lib/aggregation"
	"github.com/lca1/unlynx/lib/store"
	"github.com/lca1/unlynx/lib/tools"
)

// LocalAggregationProtocolName is the registered name for the local aggregation protocol.
const LocalAggregationProtocolName = "LocalAggregation"

func init() {
	if _, err := onet.GlobalProtocolRegister(LocalAggregationProtocolName, NewLocalAggregationProtocol); err != nil {
		log.Fatal("Error registering <LocalAggregationProtocol>")
	}
}

// Protocol
//______________________________________________________________________________________________________________________

var finalResultAggr = make(chan map[libunlynx.GroupingKey]libunlynx.FilteredResponse)

// LocalAggregationProtocol is a struct holding the state of a protocol instance.
type LocalAggregationProtocol struct {
	*onet.TreeNodeInstance

	// Protocol feedback channel
	FeedbackChannel chan map[libunlynx.GroupingKey]libunlynx.FilteredResponse

	// Protocol state data
	TargetOfAggregation []libunlynx.FilteredResponseDet
	Proofs              bool
}

// NewLocalAggregationProtocol is constructor of Local Aggregation protocol instances.
func NewLocalAggregationProtocol(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	pvp := &LocalAggregationProtocol{
		TreeNodeInstance: n,
		FeedbackChannel:  make(chan map[libunlynx.GroupingKey]libunlynx.FilteredResponse),
	}

	return pvp, nil
}

// Start is called at the root to start the execution of the key switching.
func (p *LocalAggregationProtocol) Start() error {

	log.Lvl1(p.ServerIdentity(), "started a local aggregation Protocol")
	roundComput := libunlynx.StartTimer(p.Name() + "_LocalAggregation(PROTOCOL)")

	resultingMap := make(map[libunlynx.GroupingKey]libunlynx.FilteredResponse)

	cvMap := make(map[libunlynx.GroupingKey][]libunlynx.CipherVector)
	for _, v := range p.TargetOfAggregation {
		libunlynxtools.AddInMap(resultingMap, v.DetTagGroupBy, v.Fr)

		if p.Proofs {
			libunlynxstore.FormatAggregationProofs(v, cvMap)
		}

	}

	libunlynx.EndTimer(roundComput)
	roundProof := libunlynx.StartTimer(p.Name() + "_LocalAggregation(PROOFS)")

	if p.Proofs {
		for k, v := range cvMap {
			palp := libunlynxaggr.AggregationListProofCreation(v, resultingMap[k].AggregatingAttributes)
			/* TODO: delete this*/
			if libunlynxaggr.AggregationListProofVerification(palp, 1.0) == false {
				log.Fatal("nooo")
			}
		}
	}

	libunlynx.EndTimer(roundProof)

	finalResultAggr <- resultingMap

	return nil
}

// Dispatch is called on each node. It waits for incoming messages and handle them.
func (p *LocalAggregationProtocol) Dispatch() error {
	defer p.Done()

	aux := <-finalResultAggr
	p.FeedbackChannel <- aux
	return nil
}
