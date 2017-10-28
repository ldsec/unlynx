// Package protocols contains the LocalClearAggregation Protocol and its only purpose is to simulate aggregations done locally
// For example, it can be used to simulate a data provider doing some Pre-processing on its data
package protocols

import (
	"github.com/lca1/unlynx/lib"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/log"
)

// LocalClearAggregationProtocolName is the registered name for the local cleartext aggregation protocol.
const LocalClearAggregationProtocolName = "LocalClearAggregation"

func init() {
	onet.GlobalProtocolRegister(LocalClearAggregationProtocolName, NewLocalClearAggregationProtocol)
}

// Protocol
//______________________________________________________________________________________________________________________

// LocalClearAggregationProtocol is a struct holding the state of a protocol instance.
type LocalClearAggregationProtocol struct {
	*onet.TreeNodeInstance

	// Protocol feedback channel
	FeedbackChannel chan []lib.DpClearResponse

	// Protocol state data
	TargetOfAggregation []lib.DpClearResponse
}

// NewLocalClearAggregationProtocol is constructor of Proofs Verification protocol instances.
func NewLocalClearAggregationProtocol(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	pvp := &LocalClearAggregationProtocol{
		TreeNodeInstance: n,
		FeedbackChannel:  make(chan []lib.DpClearResponse),
	}

	return pvp, nil
}

var finalResultClearAggr = make(chan []lib.DpClearResponse)

// Start is called at the root to start the execution of the local clear aggregation.
func (p *LocalClearAggregationProtocol) Start() error {
	log.Lvl1(p.ServerIdentity(), "started a local clear aggregation protocol")
	roundComput := lib.StartTimer(p.Name() + "_LocalClearAggregation(START)")
	result := lib.AddInClear(p.TargetOfAggregation)
	lib.EndTimer(roundComput)
	finalResultClearAggr <- result
	return nil
}

// Dispatch is called on each node. It waits for incoming messages and handle them.
func (p *LocalClearAggregationProtocol) Dispatch() error {
	aux := <-finalResultClearAggr
	p.FeedbackChannel <- aux
	return nil
}
