// Package protocols contains the shuffling protocol which permits to rerandomize and shuffle a list of client responses.
// The El-Gamal encrypted client response should be encrypted by the collective public key of the cothority.
// In that case, each cothority server (node) can  homomorphically rerandomize and shuffle the client responses.
// This is done by creating a circuit between the servers. The client response is sent through this circuit and
// each server applies its transformation on it and forwards it to the next node in the circuit
// until it comes back to the server who started the protocol.
package protocols

import (
	"errors"

	"github.com/JoaoAndreSa/MedCo/lib"
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/dedis/onet.v1/network"
	"sync"
)

// ShufflingProtocolName is the registered name for the neff shuffle protocol.
const ShufflingProtocolName = "Shuffling"

func init() {
	network.RegisterMessage(ShufflingMessage{})
	network.RegisterMessage(ShufflingBytesMessage{})
	network.RegisterMessage(SBLengthMessage{})
	onet.GlobalProtocolRegister(ShufflingProtocolName, NewShufflingProtocol)
}

// Messages
//______________________________________________________________________________________________________________________

// ShufflingMessage represents a message containing data to shuffle
type ShufflingMessage struct {
	Data []lib.ProcessResponse
}

// ShufflingBytesMessage represents a shuffling message in bytes
type ShufflingBytesMessage struct {
	Data []byte
}

// SBLengthMessage is a message containing the lengths to read a shuffling message in bytes
type SBLengthMessage struct {
	GacbLength  int
	AabLength   int
	PgaebLength int
}

// Structs
//______________________________________________________________________________________________________________________

// ShufflingStruct contains a shuffling message
type shufflingStruct struct {
	*onet.TreeNode
	ShufflingMessage
}

// ShufflingBytesStruct contains a shuffling message in bytes
type shufflingBytesStruct struct {
	*onet.TreeNode
	ShufflingBytesMessage
}

// SbLengthStruct contains a length message
type sbLengthStruct struct {
	*onet.TreeNode
	SBLengthMessage
}

// Protocol
//______________________________________________________________________________________________________________________

// ShufflingProtocol hold the state of a shuffling protocol instance.
type ShufflingProtocol struct {
	*onet.TreeNodeInstance

	// Protocol feedback channel
	FeedbackChannel chan []lib.ProcessResponse

	// Protocol communication channels
	LengthNodeChannel         chan sbLengthStruct
	PreviousNodeInPathChannel chan shufflingBytesStruct

	// Protocol state data
	nextNodeInCircuit *onet.TreeNode
	TargetOfShuffle   *[]lib.ProcessResponse

	CollectiveKey abstract.Point //only use in order to test the protocol
	Proofs        bool
	Precomputed   []lib.CipherVectorScalar
}

// NewShufflingProtocol constructs neff shuffle protocol instances.
func NewShufflingProtocol(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	dsp := &ShufflingProtocol{
		TreeNodeInstance: n,
		FeedbackChannel:  make(chan []lib.ProcessResponse),
	}

	if err := dsp.RegisterChannel(&dsp.PreviousNodeInPathChannel); err != nil {
		return nil, errors.New("couldn't register data reference channel: " + err.Error())
	}

	if err := dsp.RegisterChannel(&dsp.LengthNodeChannel); err != nil {
		return nil, errors.New("couldn't register data reference channel: " + err.Error())
	}

	var i int
	var node *onet.TreeNode
	var nodeList = n.Tree().List()
	for i, node = range nodeList {
		if n.TreeNode().Equal(node) {
			dsp.nextNodeInCircuit = nodeList[(i+1)%len(nodeList)]
			break
		}
	}
	return dsp, nil
}

// Start is called at the root node and starts the execution of the protocol.
func (p *ShufflingProtocol) Start() error {

	roundTotalStart := lib.StartTimer(p.Name() + "_Shuffling(START)")

	if p.TargetOfShuffle == nil {
		return errors.New("No map given as shuffling target")
	}

	nbrClientResponses := len(*p.TargetOfShuffle)
	log.Lvl1("["+p.Name()+"]", " started a Shuffling Protocol (", nbrClientResponses, " responses)")

	shuffleTarget := *p.TargetOfShuffle
	collectiveKey := p.Roster().Aggregate
	if p.CollectiveKey != nil {
		//test
		collectiveKey = p.CollectiveKey
		log.LLvl1("Key used is ", collectiveKey)
	}
	roundShufflingStart := lib.StartTimer(p.Name() + "_Shuffling(START-noProof)")

	if p.Precomputed != nil {
		log.LLvl1(p.Name(), " uses pre-computation in shuffling")
	}

	shuffledData, pi, beta := lib.ShuffleSequence(shuffleTarget, nil, collectiveKey, p.Precomputed)
	lib.EndTimer(roundShufflingStart)
	roundShufflingStartProof := lib.StartTimer(p.Name() + "_Shuffling(START-Proof)")

	if p.Proofs {
		proof := lib.ShufflingProofCreation(shuffleTarget, shuffledData, nil, collectiveKey, beta, pi)
		//dummy publication
		_ = proof
	}

	lib.EndTimer(roundShufflingStartProof)
	lib.EndTimer(roundTotalStart)

	sendingStart := lib.StartTimer(p.Name() + "_Sending")

	message := ShufflingBytesMessage{}
	var cgaLength, eaaLength, egaLength int
	message.Data, cgaLength, eaaLength, egaLength = (&ShufflingMessage{shuffledData}).ToBytes()

	p.sendToNext(&SBLengthMessage{cgaLength, eaaLength, egaLength})
	p.sendToNext(&message)

	lib.EndTimer(sendingStart)

	return nil
}

// Dispatch is called on each tree node. It waits for incoming messages and handles them.
func (p *ShufflingProtocol) Dispatch() error {

	shufflingLength := <-p.LengthNodeChannel

	receiving := lib.StartTimer(p.Name() + "_Receiving")
	tmp := <-p.PreviousNodeInPathChannel

	sm := ShufflingMessage{}
	sm.FromBytes(tmp.Data, shufflingLength.GacbLength, shufflingLength.AabLength, shufflingLength.PgaebLength)
	shufflingTarget := sm.Data

	lib.EndTimer(receiving)

	roundTotalComputation := lib.StartTimer(p.Name() + "_Shuffling(DISPATCH)")

	collectiveKey := p.Roster().Aggregate //shuffling is by default done with collective authority key

	if p.CollectiveKey != nil {
		//test
		collectiveKey = p.CollectiveKey
		log.LLvl1("Key used: ", collectiveKey)
	}

	shuffledData := shufflingTarget
	var pi []int
	var beta [][]abstract.Scalar

	if !p.IsRoot() {
		roundShuffle := lib.StartTimer(p.Name() + "_Shuffling(DISPATCH-noProof)")

		shuffledData, pi, beta = lib.ShuffleSequence(shufflingTarget, nil, collectiveKey, p.Precomputed)

		lib.EndTimer(roundShuffle)
		roundShuffleProof := lib.StartTimer("_Shuffling(DISPATCH-Proof)")

		if p.Proofs {
			proof := lib.ShufflingProofCreation(shufflingTarget, shuffledData, nil, collectiveKey, beta, pi)
			//dummy publication
			_ = proof
		}
		lib.EndTimer(roundShuffleProof)

	}
	shufflingTarget = shuffledData

	if p.IsRoot() {
		log.Lvl1(p.ServerIdentity(), " completed shuffling (", len(shufflingTarget), " responses)")
	} else {
		log.Lvl1(p.ServerIdentity(), " carried on shuffling.")
	}

	lib.EndTimer(roundTotalComputation)

	// If this tree node is the root, then protocol reached the end.
	if p.IsRoot() {
		p.FeedbackChannel <- shufflingTarget
	} else {
		// Forward switched message.
		sending := lib.StartTimer(p.Name() + "_Sending")

		message := ShufflingBytesMessage{}
		var cgaLength, eaaLength, egaLength int
		message.Data, cgaLength, eaaLength, egaLength = (&ShufflingMessage{shuffledData}).ToBytes()

		p.sendToNext(&SBLengthMessage{cgaLength, eaaLength, egaLength})
		p.sendToNext(&message)

		lib.EndTimer(sending)
	}

	return nil
}

// Sends the message msg to the next node in the circuit based on the next TreeNode in Tree.List() If not visited yet.
// If the message already visited the next node, doesn't send and returns false. Otherwise, return true.
func (p *ShufflingProtocol) sendToNext(msg interface{}) {
	err := p.SendTo(p.nextNodeInCircuit, msg)
	if err != nil {
		log.Lvl1("Had an error sending a message: ", err)
	}
}

// Conversion
//______________________________________________________________________________________________________________________

// ToBytes converts a ShufflingMessage to a byte array
func (sm *ShufflingMessage) ToBytes() ([]byte, int, int, int) {
	b := make([]byte, 0)
	bb := make([][]byte, len((*sm).Data))

	var gacbLength int
	var aabLength int
	var pgaebLength int

	wg := lib.StartParallelize(len((*sm).Data))
	var mutexD sync.Mutex
	for i := range (*sm).Data {
		if lib.PARALLELIZE {
			go func(i int) {
				defer wg.Done()

				mutexD.Lock()
				data := (*sm).Data[i]
				mutexD.Unlock()

				aux, gacbAux, aabAux, pgaebAux := data.ToBytes()

				mutexD.Lock()
				bb[i] = aux
				gacbLength = gacbAux
				aabLength = aabAux
				pgaebLength = pgaebAux
				mutexD.Unlock()
			}(i)
		} else {
			bb[i], gacbLength, aabLength, pgaebLength = (*sm).Data[i].ToBytes()
		}

	}
	lib.EndParallelize(wg)

	for _, el := range bb {
		b = append(b, el...)
	}

	return b, gacbLength, aabLength, pgaebLength
}

// FromBytes converts a byte array to a ShufflingMessage. Note that you need to create the (empty) object beforehand.
func (sm *ShufflingMessage) FromBytes(data []byte, gacbLength, aabLength, pgaebLength int) {
	var nbrData int

	elementLength := (gacbLength*64 + aabLength*64 + pgaebLength*64) //CAUTION: hardcoded 64 (size of el-gamal element C,K)
	nbrData = len(data) / elementLength

	(*sm).Data = make([]lib.ProcessResponse, nbrData)
	wg := lib.StartParallelize(nbrData)
	for i := 0; i < nbrData; i++ {
		v := data[i*elementLength : i*elementLength+elementLength]
		if lib.PARALLELIZE {
			go func(v []byte, i int) {
				defer wg.Done()
				(*sm).Data[i].FromBytes(v, gacbLength, aabLength, pgaebLength)
			}(v, i)
		} else {
			(*sm).Data[i].FromBytes(v, gacbLength, aabLength, pgaebLength)
		}

	}
	lib.EndParallelize(wg)
}
