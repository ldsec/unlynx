// Package protocols contains the pipeline protocol which handles the pipeline meaning the flow of executions of
// specific protocols.
// The complete execution is separated into four phases and this protocol handles
// the "synchronization" of the protocols. At first, it triggers all the nodes to
// run a shuffling (1st phase). Then it waits until all responses are received by
// the root and triggers the next phase and same after that.
package protocols

import (
	"github.com/JoaoAndreSa/MedCo/lib"
	"github.com/btcsuite/goleveldb/leveldb/errors"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/dedis/onet.v1/network"
)

// MedcoServiceProtocolName is the registered name for the medco service protocol.
const MedcoServiceProtocolName = "MedcoServiceProtocol"

func init() {
	onet.GlobalProtocolRegister(MedcoServiceProtocolName, NewPipelineProcotol)
	network.RegisterMessage(TriggerFlushCollectedDataMessage{})
	network.RegisterMessage(DoneFlushCollectedDataMessage{})
}

// Messages
//______________________________________________________________________________________________________________________

// ServiceInterface defines the 3 phases of a medco pipeline. The service implements this interface so the
// protocol can trigger them.
type ServiceInterface interface {
	TaggingPhase(lib.SurveyID) error
	AggregationPhase(lib.SurveyID) error
	KeySwitchingPhase(lib.SurveyID) error
	ShufflingPhase(lib.SurveyID) error
}

// TriggerFlushCollectedDataMessage is a message trigger the Map phase at all node.
type TriggerFlushCollectedDataMessage struct {
	SurveyID lib.SurveyID // Currently unused
}

// DoneFlushCollectedDataMessage is a message reporting the Map phase completion.
type DoneFlushCollectedDataMessage struct{}

// DoneProcessingMessage is a message indicating that pipeline execution complete.
type DoneProcessingMessage struct{}

// Structs
//______________________________________________________________________________________________________________________

type flushCollectedDataStruct struct {
	*onet.TreeNode
	TriggerFlushCollectedDataMessage
}

type doneFlushCollectedDataStruct struct {
	*onet.TreeNode
	DoneFlushCollectedDataMessage
}

// PipelineProtocol is a struct holding the protocol instance state
type PipelineProtocol struct {
	*onet.TreeNodeInstance

	TriggerFlushCollectedData chan flushCollectedDataStruct
	DoneFlushCollectedData    chan []doneFlushCollectedDataStruct

	FeedbackChannel chan DoneProcessingMessage

	MedcoServiceInstance ServiceInterface
	TargetSurvey         *lib.Survey

	Proofs bool
}

// NewPipelineProcotol constructor of a pipeline protocol.
func NewPipelineProcotol(tni *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	protocol := &PipelineProtocol{TreeNodeInstance: tni,
		FeedbackChannel: make(chan DoneProcessingMessage)}

	chans := []interface{}{&protocol.TriggerFlushCollectedData, &protocol.DoneFlushCollectedData}
	for _, c := range chans {
		if err := protocol.RegisterChannel(c); err != nil {
			return nil, errors.New("couldn't register data reference channel: " + err.Error())
		}
	}
	return protocol, nil
}

// Start is called at the root. It starts the execution of the protocol.
func (p *PipelineProtocol) Start() error {

	if p.MedcoServiceInstance == nil {
		return errors.New("No Medco Service pointer provided")
	}
	if p.TargetSurvey == nil {
		return errors.New("No Target Survey ID pointer provided")
	}

	log.Lvl1(p.ServerIdentity(), " starts a Medco Service Protocol.")
	p.Broadcast(&TriggerFlushCollectedDataMessage{p.TargetSurvey.ID})

	return nil
}

// Dispatch is called at all nodes and handles the incoming messages.
func (p *PipelineProtocol) Dispatch() error {

	startT := lib.StartTimer(p.Name() + "_ShufflingPhase+TaggingPhase")

	if p.TargetSurvey.DataToProcess == nil { // normal use of Unlynx/medco
		if p.IsRoot() {
			start := lib.StartTimer(p.Name() + "_ShufflingPhase")

			p.MedcoServiceInstance.ShufflingPhase(p.TargetSurvey.ID)
			p.Broadcast(&TriggerFlushCollectedDataMessage{p.TargetSurvey.ID})
			lib.EndTimer(start)
		} else {
			msg := <-p.TriggerFlushCollectedData
			start := lib.StartTimer(p.Name() + "_ShufflingPhase")

			p.MedcoServiceInstance.ShufflingPhase(msg.SurveyID)
			p.Broadcast(&TriggerFlushCollectedDataMessage{msg.SurveyID})
			lib.EndTimer(start)
		}

		// 1st phase (optional) : Grouping
		//if p.TargetSurvey.SurveyDescription.GroupingAttributesCount > 0 {
		if p.IsRoot() {
			start := lib.StartTimer(p.Name() + "_TaggingPhase")

			p.MedcoServiceInstance.TaggingPhase(p.TargetSurvey.ID)

			lib.EndTimer(start)

			<-p.DoneFlushCollectedData

		} else {

			msg := <-p.TriggerFlushCollectedData

			start := lib.StartTimer(p.Name() + "_TaggingPhase")

			p.MedcoServiceInstance.TaggingPhase(msg.SurveyID)

			lib.EndTimer(start)
			if !p.IsLeaf() {
				<-p.DoneFlushCollectedData
			}
			p.SendToParent(&DoneFlushCollectedDataMessage{})
		}
		//}

		lib.EndTimer(startT)

		// 2nd phase: Aggregating
		if p.IsRoot() {
			start := lib.StartTimer(p.Name() + "_AggregationPhase")

			p.MedcoServiceInstance.AggregationPhase(p.TargetSurvey.ID)

			lib.EndTimer(start)
		}

		// 3rd phase: Key Switching
		if p.IsRoot() {
			start := lib.StartTimer(p.Name() + "_KeySwitchingPhase")

			p.MedcoServiceInstance.KeySwitchingPhase(p.TargetSurvey.ID)

			lib.EndTimer(start)

			p.FeedbackChannel <- DoneProcessingMessage{}
		}
	} else {

		if p.IsRoot() {
			p.MedcoServiceInstance.TaggingPhase(p.TargetSurvey.ID)
			p.MedcoServiceInstance.AggregationPhase(p.TargetSurvey.ID)
			p.FeedbackChannel <- DoneProcessingMessage{}
		}

	}

	return nil
}
