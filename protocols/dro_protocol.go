package protocols

import (
	"github.com/JoaoAndreSa/MedCo/lib"
	"github.com/dedis/cothority/log"
	"gopkg.in/dedis/onet.v1"
)

// DROProtocolName is the registered name for the neff shuffle protocol.
const DROProtocolName = "DRO"

//TODO: change this form hardcoded
// noise values
var noiseArray []int64

func init() {
	//TODO: number of noise values hardcoded
	noiseArray = generateNoiseValues(1000)

	onet.GlobalProtocolRegister(DROProtocolName, NewDROProtocol)
}

// Protocol
//______________________________________________________________________________________________________________________

// DROProtocol hold the state of a DRO protocol instance.
type DROProtocol struct {
	*onet.TreeNodeInstance

	// Protocol feedback channel
	FeedbackChannel chan lib.ClientResponse
}

// NewDROProtocol constructs the Distributed Results Obfuscation protocol instances.
func NewDROProtocol(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	dsp := &DROProtocol{
		TreeNodeInstance: n,
		FeedbackChannel:  make(chan lib.ClientResponse),
	}
	return dsp, nil
}

// Start is called at the root node and starts the execution of the protocol.
func (p *DROProtocol) Start() error {

	tn := p.TreeNodeInstance

	pi, err := NewShufflingProtocol(tn)
	shuffle := pi.(*ShufflingProtocol)
	shuffle.Proofs = true
	shuffle.Precomputed = nil

	clientResponses := make([]lib.ClientResponse, 0)

	for _, v := range noiseArray {
		clientResponses = append(clientResponses, lib.ClientResponse{GroupingAttributesClear: "", ProbaGroupingAttributesEnc: nil, AggregatingAttributes: *lib.EncryptIntVector(p.Roster().Aggregate, []int64{v})})
	}

	if tn.IsRoot() {
		shuffle.TargetOfShuffle = &clientResponses
	}

	go pi.Start()
	go pi.Dispatch()

	shufflingResult := <-pi.(*ShufflingProtocol).FeedbackChannel
	log.LLvl1(len(shufflingResult))
	p.FeedbackChannel <- shufflingResult[0]

	return err
}

// Dispatch is called on each tree node. It waits for incoming messages and handles them.
func (p *DROProtocol) Dispatch() error {

	return nil
}

// Noise Generation
//______________________________________________________________________________________________________________________

// generateNoiseValues generates a number of n noise values from a given probabilistic distribution
func generateNoiseValues(n int) []int64 {

	//just for testing
	example := [...]int64{-4, -3, -2, -2, -1, -1, -1, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 3, 4}
	noise := make([]int64, 0)

	for i := 0; i < n; i++ {
		noise = append(noise, example[i%len(example)])
	}
	return noise
}
