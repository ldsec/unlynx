// Package protocolsunlynx implement the shuffling protocol. It rerandomizes and shuffles a list of ciphertexts.
// This operates in a circuit between the servers: the data is sent sequentially through this circuit and each
// server applies its transformation.
package protocolsunlynx

import (
	"fmt"
	"time"

	"github.com/ldsec/unlynx/lib"
	"github.com/ldsec/unlynx/lib/shuffle"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
)

// ShufflingProtocolName is the registered name for the neff shuffle protocol.
const ShufflingProtocolName = "Shuffling"

func init() {
	network.RegisterMessage(ShufflingMessage{})
	network.RegisterMessage(ShufflingBytesMessage{})
	network.RegisterMessage(ShufflingBytesMessageLength{})
	if _, err := onet.GlobalProtocolRegister(ShufflingProtocolName, NewShufflingProtocol); err != nil {
		log.Fatal("Failed to register the <Shuffling> protocol: ", err)
	}
}

// Messages
//______________________________________________________________________________________________________________________

// ShufflingMessage represents a message containing data to shuffle
type ShufflingMessage struct {
	Data []libunlynx.CipherVector
}

// ShufflingBytesMessage represents a shuffling message in bytes
type ShufflingBytesMessage struct {
	Data []byte
}

// ShufflingBytesMessageLength is a message containing the lengths to read a shuffling message in bytes
type ShufflingBytesMessageLength struct {
	CVLengths []byte
}

// Structs
//______________________________________________________________________________________________________________________

// shufflingBytesStruct contains a shuffling message in bytes
type shufflingBytesStruct struct {
	*onet.TreeNode
	ShufflingBytesMessage
}

// shufflingBytesLengthStruct contains a length message
type shufflingBytesLengthStruct struct {
	*onet.TreeNode
	ShufflingBytesMessageLength
}

// proofShuffleFunction defines a function that does 'stuff' with the shuffle proofs
type proofShuffleFunction func([]libunlynx.CipherVector, []libunlynx.CipherVector, kyber.Point, [][]kyber.Scalar, []int) *libunlynxshuffle.PublishedShufflingProof

// Protocol
//______________________________________________________________________________________________________________________

// ShufflingProtocol hold the state of a shuffling protocol instance.
type ShufflingProtocol struct {
	*onet.TreeNodeInstance

	// Protocol feedback channel
	FeedbackChannel chan []libunlynx.CipherVector

	// Protocol communication channels
	LengthNodeChannel         chan shufflingBytesLengthStruct
	PreviousNodeInPathChannel chan shufflingBytesStruct

	// Protocol state data
	ShuffleTarget     *[]libunlynx.CipherVector
	Precomputed       []libunlynxshuffle.CipherVectorScalar
	nextNodeInCircuit *onet.TreeNode

	// Proofs
	Proofs    bool
	ProofFunc proofShuffleFunction             // proof function for when we want to do something different with the proofs (e.g. insert in the blockchain)
	MapPIs    map[string]onet.ProtocolInstance // protocol instances to be able to call protocols inside protocols (e.g. proof_collection_protocol)

	// Test (only use in order to test the protocol)
	CollectiveKey kyber.Point
	ExecTimeStart time.Duration
	ExecTime      time.Duration
}

// NewShufflingProtocol constructs neff shuffle protocol instances.
func NewShufflingProtocol(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	dsp := &ShufflingProtocol{
		TreeNodeInstance: n,
		FeedbackChannel:  make(chan []libunlynx.CipherVector),
	}

	if err := dsp.RegisterChannel(&dsp.PreviousNodeInPathChannel); err != nil {
		return nil, fmt.Errorf("couldn't register data reference channel: %v", err)
	}

	if err := dsp.RegisterChannel(&dsp.LengthNodeChannel); err != nil {
		return nil, fmt.Errorf("couldn't register data reference channel: %v", err)
	}

	// choose next node in circuit
	nodeList := n.Tree().List()
	for i, node := range nodeList {
		if n.TreeNode().Equal(node) {
			dsp.nextNodeInCircuit = nodeList[(i+1)%len(nodeList)]
			break
		}
	}

	return dsp, nil
}

// Start is called at the root node and starts the execution of the protocol.
func (p *ShufflingProtocol) Start() error {

	shufflingStart := libunlynx.StartTimer(p.Name() + "_Shuffling(START)")

	if p.ShuffleTarget == nil {
		return fmt.Errorf("no map given as shuffling target")
	}

	p.ExecTimeStart = 0
	p.ExecTime = 0
	timer := time.Now()

	nbrProcessResponses := len(*p.ShuffleTarget)
	log.Lvl1("["+p.Name()+"]", " started a Shuffling Protocol (", nbrProcessResponses, " responses)")

	shuffleTarget := *p.ShuffleTarget

	collectiveKey := p.Roster().Aggregate
	// when testing protocol
	if p.CollectiveKey != nil {
		collectiveKey = p.CollectiveKey
	}

	shufflingStartNoProof := libunlynx.StartTimer(p.Name() + "_Shuffling(START-noProof)")

	if p.Precomputed != nil {
		log.Lvl1(p.Name(), " uses pre-computation in shuffling")
	}

	shuffledData, pi, beta := libunlynxshuffle.ShuffleSequence(shuffleTarget, libunlynx.SuiTe.Point().Base(), collectiveKey, p.Precomputed)

	libunlynx.EndTimer(shufflingStartNoProof)

	shufflingStartProof := libunlynx.StartTimer(p.Name() + "_Shuffling(START-Proof)")

	if p.Proofs {
		p.ProofFunc(shuffleTarget, shuffledData, collectiveKey, beta, pi)
	}

	libunlynx.EndTimer(shufflingStartProof)
	libunlynx.EndTimer(shufflingStart)

	p.ExecTimeStart += time.Since(timer)

	message := ShufflingBytesMessage{}
	var cvLengthsByte []byte
	var err error

	message.Data, cvLengthsByte, err = (&ShufflingMessage{shuffledData}).ToBytes()
	if err != nil {
		return err
	}

	if err := p.sendToNext(&ShufflingBytesMessageLength{CVLengths: cvLengthsByte}); err != nil {
		return err
	}
	if err := p.sendToNext(&message); err != nil {
		return err
	}
	return nil
}

// Dispatch is called on each tree node. It waits for incoming messages and handles them.
func (p *ShufflingProtocol) Dispatch() error {
	defer p.Done()

	var shufflingBytesMessageLength shufflingBytesLengthStruct
	select {
	case shufflingBytesMessageLength = <-p.LengthNodeChannel:
	case <-time.After(libunlynx.TIMEOUT):
		return fmt.Errorf(p.ServerIdentity().String() + " didn't get the <shufflingBytesMessageLength> on time")
	}

	var sbs shufflingBytesStruct
	select {
	case sbs = <-p.PreviousNodeInPathChannel:
	case <-time.After(libunlynx.TIMEOUT):
		return fmt.Errorf(p.ServerIdentity().String() + " didn't get the <sbs> on time")
	}

	sm := ShufflingMessage{}
	if err := sm.FromBytes(sbs.Data, shufflingBytesMessageLength.CVLengths); err != nil {
		return err
	}
	shuffleTarget := sm.Data

	timer := time.Now()
	shufflingDispatch := libunlynx.StartTimer(p.Name() + "_Shuffling(DISPATCH)")

	collectiveKey := p.Roster().Aggregate
	// when testing protocol
	if p.CollectiveKey != nil {
		collectiveKey = p.CollectiveKey
	}

	if p.Precomputed != nil {
		log.Lvl1(p.Name(), " uses pre-computation in shuffling")
	}

	shuffledData := shuffleTarget
	var pi []int
	var beta [][]kyber.Scalar

	if p.IsRoot() == false {
		shufflingDispatchNoProof := libunlynx.StartTimer(p.Name() + "_Shuffling(DISPATCH-noProof)")

		shuffledData, pi, beta = libunlynxshuffle.ShuffleSequence(shuffleTarget, libunlynx.SuiTe.Point().Base(), collectiveKey, p.Precomputed)

		libunlynx.EndTimer(shufflingDispatchNoProof)

		shufflingDispatchProof := libunlynx.StartTimer("_Shuffling(DISPATCH-Proof)")

		if p.Proofs {
			p.ProofFunc(shuffleTarget, shuffledData, collectiveKey, beta, pi)
		}

		libunlynx.EndTimer(shufflingDispatchProof)

	}

	shuffleTarget = shuffledData

	if p.IsRoot() {
		log.Lvl1(p.ServerIdentity(), " completed shuffling (", len(shuffleTarget), " responses)")
	} else {
		log.Lvl1(p.ServerIdentity(), " carried on shuffling.")
	}

	libunlynx.EndTimer(shufflingDispatch)

	// If this tree node is the root, then protocol reached the end.
	if p.IsRoot() {
		p.ExecTime += time.Since(timer)
		p.FeedbackChannel <- shuffleTarget
	} else {
		// Forward switched message.
		message := ShufflingBytesMessage{}
		var cvBytesLengths []byte
		var err error
		message.Data, cvBytesLengths, err = (&ShufflingMessage{shuffledData}).ToBytes()
		if err != nil {
			return err
		}

		if err := p.sendToNext(&ShufflingBytesMessageLength{cvBytesLengths}); err != nil {
			return err
		}
		if err := p.sendToNext(&message); err != nil {
			return err
		}
	}

	return nil
}

// Sends the message msg to the next node in the circuit based on the next TreeNode in Tree.List().
func (p *ShufflingProtocol) sendToNext(msg interface{}) error {
	err := p.SendTo(p.nextNodeInCircuit, msg)
	if err != nil {
		return err
	}
	return nil
}

// Marshal
//______________________________________________________________________________________________________________________

// ToBytes converts a ShufflingMessage to a byte array
func (sm *ShufflingMessage) ToBytes() ([]byte, []byte, error) {
	return libunlynx.ArrayCipherVectorToBytes(sm.Data)
}

// FromBytes converts a byte array to a ShufflingMessage. Note that you need to create the (empty) object beforehand.
func (sm *ShufflingMessage) FromBytes(data []byte, cvLengthsByte []byte) error {
	var err error
	(*sm).Data, err = libunlynx.FromBytesToArrayCipherVector(data, cvLengthsByte)
	if err != nil {
		return err
	}
	return nil
}
