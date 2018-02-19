// Package protocolsUnLynx contains LocalAggregationProtocol and its only purpose is to simulate aggregations done locally
// For example, it can be used to simulate a data provider doing some pre-processing on its data
package protocolsUnLynx

import (
	"github.com/lca1/unlynx/lib"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/log"
)

// LocalAggregationProtocolName is the registered name for the local aggregation protocol.
const LocalAggregationProtocolName = "LocalAggregation"

func init() {
	onet.GlobalProtocolRegister(LocalAggregationProtocolName, NewLocalAggregationProtocol)
}

// Protocol
//______________________________________________________________________________________________________________________

var finalResultAggr = make(chan map[libUnLynx.GroupingKey]libUnLynx.FilteredResponse)

// LocalAggregationProtocol is a struct holding the state of a protocol instance.
type LocalAggregationProtocol struct {
	*onet.TreeNodeInstance

	// Protocol feedback channel
	FeedbackChannel chan map[libUnLynx.GroupingKey]libUnLynx.FilteredResponse

	// Protocol state data
	TargetOfAggregation []libUnLynx.FilteredResponseDet
	Proofs              bool
}

// NewLocalAggregationProtocol is constructor of Local Aggregation protocol instances.
func NewLocalAggregationProtocol(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	pvp := &LocalAggregationProtocol{
		TreeNodeInstance: n,
		FeedbackChannel:  make(chan map[libUnLynx.GroupingKey]libUnLynx.FilteredResponse),
	}

	return pvp, nil
}

// Start is called at the root to start the execution of the key switching.
func (p *LocalAggregationProtocol) Start() error {

	log.Lvl1(p.ServerIdentity(), "started a local aggregation Protocol")
	roundComput := libUnLynx.StartTimer(p.Name() + "_LocalAggregation(PROTOCOL)")

	resultingMap := make(map[libUnLynx.GroupingKey]libUnLynx.FilteredResponse)

	for _, v := range p.TargetOfAggregation {
		libUnLynx.AddInMap(resultingMap, v.DetTagGroupBy, v.Fr)
	}

	libUnLynx.EndTimer(roundComput)
	roundProof := libUnLynx.StartTimer(p.Name() + "_LocalAggregation(PROOFS)")

	if p.Proofs {
		PublishedAggregationProof := libUnLynx.AggregationProofCreation(p.TargetOfAggregation, resultingMap)
		//publication
		_ = PublishedAggregationProof
	}

	libUnLynx.EndTimer(roundProof)

	finalResultAggr <- resultingMap

	return nil
}

// Dispatch is called on each node. It waits for incoming messages and handle them.
func (p *LocalAggregationProtocol) Dispatch() error {
	aux := <-finalResultAggr
	p.FeedbackChannel <- aux
	return nil
}
