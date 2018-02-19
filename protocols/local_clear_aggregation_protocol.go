// Package protocolsUnLynx contains the LocalClearAggregation Protocol and its only purpose is to simulate aggregations done locally
// For example, it can be used to simulate a data provider doing some pre-processing on its data
package protocolsUnLynx

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
	FeedbackChannel chan []libUnLynx.DpClearResponse

	// Protocol state data
	TargetOfAggregation []libUnLynx.DpClearResponse
}

// NewLocalClearAggregationProtocol is constructor of Proofs Verification protocol instances.
func NewLocalClearAggregationProtocol(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	pvp := &LocalClearAggregationProtocol{
		TreeNodeInstance: n,
		FeedbackChannel:  make(chan []libUnLynx.DpClearResponse),
	}

	return pvp, nil
}

var finalResultClearAggr = make(chan []libUnLynx.DpClearResponse)

// Start is called at the root to start the execution of the local clear aggregation.
func (p *LocalClearAggregationProtocol) Start() error {
	log.Lvl1(p.ServerIdentity(), "started a local clear aggregation protocol")
	roundComput := libUnLynx.StartTimer(p.Name() + "_LocalClearAggregation(START)")
	result := libUnLynx.AddInClear(p.TargetOfAggregation)
	libUnLynx.EndTimer(roundComput)
	finalResultClearAggr <- result
	return nil
}

// Dispatch is called on each node. It waits for incoming messages and handle them.
func (p *LocalClearAggregationProtocol) Dispatch() error {
	aux := <-finalResultClearAggr
	p.FeedbackChannel <- aux
	return nil
}
