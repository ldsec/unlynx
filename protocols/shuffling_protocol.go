// Package protocolsunlynx contains the shuffling protocol which permits to rerandomize and shuffle a list of DP responses.
// The El-Gamal encrypted DP response should be encrypted by the collective public key of the cothority.
// In that case, each cothority server (node) can  homomorphically rerandomize and shuffle the DP responses.
// This is done by creating a circuit between the servers. The DP response is sent through this circuit and
// each server applies its transformation on it and forwards it to the next node in the circuit
// until it comes back to the server who started the protocol.
package protocolsunlynx

import (
	"errors"

	"github.com/dedis/kyber"
	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
	"github.com/dedis/onet/network"
	"github.com/lca1/unlynx/lib"
	"sync"
	"time"
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
	Data []libunlynx.CipherVector
}

// ShufflingBytesMessage represents a shuffling message in bytes
type ShufflingBytesMessage struct {
	Data []byte
}

// SBLengthMessage is a message containing the lengths to read a shuffling message in bytes
type SBLengthMessage struct {
	CVLengths []byte
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
	FeedbackChannel chan []libunlynx.CipherVector

	// Protocol communication channels
	LengthNodeChannel         chan sbLengthStruct
	PreviousNodeInPathChannel chan shufflingBytesStruct

	ExecTimeStart time.Duration
	ExecTime      time.Duration

	// Protocol state data
	nextNodeInCircuit *onet.TreeNode
	TargetOfShuffle   *[]libunlynx.CipherVector

	CollectiveKey kyber.Point //only use in order to test the protocol
	Proofs        bool
	Precomputed   []libunlynx.CipherVectorScalar
}

// NewShufflingProtocol constructs neff shuffle protocol instances.
func NewShufflingProtocol(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	dsp := &ShufflingProtocol{
		TreeNodeInstance: n,
		FeedbackChannel:  make(chan []libunlynx.CipherVector),
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

	roundTotalStart := libunlynx.StartTimer(p.Name() + "_Shuffling(START)")

	if p.TargetOfShuffle == nil {
		return errors.New("No map given as shuffling target")
	}

	p.ExecTimeStart = 0
	p.ExecTime = 0
	startT := time.Now()

	nbrProcessResponses := len(*p.TargetOfShuffle)
	log.Lvl1("["+p.Name()+"]", " started a Shuffling Protocol (", nbrProcessResponses, " responses)")

	shuffleTarget := *p.TargetOfShuffle

	collectiveKey := p.Roster().Aggregate
	if p.CollectiveKey != nil {
		//test
		collectiveKey = p.CollectiveKey
		log.Lvl1("Key used is ", collectiveKey)
	}
	roundShufflingStart := libunlynx.StartTimer(p.Name() + "_Shuffling(START-noProof)")

	if p.Precomputed != nil {
		log.Lvl1(p.Name(), " uses pre-computation in shuffling")
	}

	shuffledData, pi, beta := libunlynx.ShuffleSequence(shuffleTarget, nil, collectiveKey, p.Precomputed)
	_ = pi
	_ = beta


	libunlynx.EndTimer(roundShufflingStart)
	roundShufflingStartProof := libunlynx.StartTimer(p.Name() + "_Shuffling(START-Proof)")

	/*
	if p.Proofs {
		proof := proofs.ShufflingProofCreation(shuffleTarget, shuffledData, nil, collectiveKey, beta, pi)
		//dummy publication
		_ = proof
	}
	*/

	libunlynx.EndTimer(roundShufflingStartProof)
	libunlynx.EndTimer(roundTotalStart)

	p.ExecTimeStart += time.Since(startT)
	//sendingStart := lib.StartTimer(p.Name() + "_Sending")

	message := ShufflingBytesMessage{}
	var cvLengthsByte []byte
	message.Data, cvLengthsByte = (&ShufflingMessage{shuffledData}).ToBytes()

	sendingStart := libunlynx.StartTimer(p.Name() + "_Sending")

	p.sendToNext(&SBLengthMessage{CVLengths: cvLengthsByte})
	p.sendToNext(&message)

	libunlynx.EndTimer(sendingStart)

	return nil
}

// Dispatch is called on each tree node. It waits for incoming messages and handles them.
func (p *ShufflingProtocol) Dispatch() error {

	shufflingLength := <-p.LengthNodeChannel

	receiving := libunlynx.StartTimer(p.Name() + "_Receiving")
	tmp := <-p.PreviousNodeInPathChannel

	libunlynx.EndTimer(receiving)

	sm := ShufflingMessage{}
	sm.FromBytes(tmp.Data, shufflingLength.CVLengths)
	shufflingTarget := sm.Data

	startT := time.Now()
	roundTotalComputation := libunlynx.StartTimer(p.Name() + "_Shuffling(DISPATCH)")

	collectiveKey := p.Roster().Aggregate //shuffling is by default done with collective authority key

	if p.CollectiveKey != nil {
		//test
		collectiveKey = p.CollectiveKey
		log.Lvl1("Key used: ", collectiveKey)
	}

	if p.Precomputed != nil {
		log.Lvl1(p.Name(), " uses pre-computation in shuffling")
	}

	shuffledData := shufflingTarget

	var pi []int
	var beta [][]kyber.Scalar

	if !p.IsRoot() {
		roundShuffle := libunlynx.StartTimer(p.Name() + "_Shuffling(DISPATCH-noProof)")

		shuffledData, pi, beta = libunlynx.ShuffleSequence(shufflingTarget, nil, collectiveKey, p.Precomputed)
		_ = pi
		_ = beta

		libunlynx.EndTimer(roundShuffle)
		roundShuffleProof := libunlynx.StartTimer("_Shuffling(DISPATCH-Proof)")

		/*
		if p.Proofs {
			proof := proofs.ShufflingProofCreation(shufflingTarget, shuffledData, nil, collectiveKey, beta, pi)
			//dummy publication
			_ = proof
		}
		*/
		libunlynx.EndTimer(roundShuffleProof)

	}
	shufflingTarget = shuffledData

	if p.IsRoot() {
		log.Lvl1(p.ServerIdentity(), " completed shuffling (", len(shufflingTarget), " responses)")
	} else {
		log.Lvl1(p.ServerIdentity(), " carried on shuffling.")
	}

	libunlynx.EndTimer(roundTotalComputation)

	// If this tree node is the root, then protocol reached the end.
	if p.IsRoot() {
		p.ExecTime += time.Since(startT)
		p.FeedbackChannel <- shufflingTarget
	} else {
		// Forward switched message.
		//sending := lib.StartTimer(p.Name() + "_Sending")

		message := ShufflingBytesMessage{}
		var cvBytesLengths []byte
		message.Data, cvBytesLengths = (&ShufflingMessage{shuffledData}).ToBytes()

		sending := libunlynx.StartTimer(p.Name() + "_Sending")

		p.sendToNext(&SBLengthMessage{cvBytesLengths})
		p.sendToNext(&message)

		libunlynx.EndTimer(sending)
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
func (sm *ShufflingMessage) ToBytes() ([]byte, []byte) {
	length := len((*sm).Data)

	b := make([]byte, 0)
	bb := make([][]byte, length)
	cvLengths := make([]int, length)

	wg := libunlynx.StartParallelize(length)
	var mutexD sync.Mutex
	for i := range (*sm).Data {
		if libunlynx.PARALLELIZE {
			go func(i int) {
				defer wg.Done()

				mutexD.Lock()
				data := (*sm).Data[i]
				mutexD.Unlock()
				bb[i], cvLengths[i] = data.ToBytes()
			}(i)
		} else {
			bb[i], cvLengths[i] = (*sm).Data[i].ToBytes()
		}

	}
	libunlynx.EndParallelize(wg)
	for _, v := range bb {
		b = append(b, v...)
	}
	return b, UnsafeCastIntsToBytes(cvLengths)

	/*
	var gacbLength int
	var aabLength int
	var pgaebLength int

	wg := libunlynx.StartParallelize(len((*sm).Data))
	var mutexD sync.Mutex
	for i := range (*sm).Data {
		if libunlynx.PARALLELIZE {
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
	libunlynx.EndParallelize(wg)

	for _, el := range bb {
		b = append(b, el...)
	}

	return b, gacbLength, aabLength, pgaebLength
	*/
}

// FromBytes converts a byte array to a ShufflingMessage. Note that you need to create the (empty) object beforehand.
func (sm *ShufflingMessage) FromBytes(data []byte, cvLengthsByte []byte) {
	cvLengths := UnsafeCastBytesToInts(cvLengthsByte)
	(*sm).Data = make([]libunlynx.CipherVector, len(cvLengths))

	wg := libunlynx.StartParallelize(len(cvLengths))

	// iter over each value in the flatten data byte array
	bytePos := 0
	for i := 0; i < len(cvLengths); i++ {
		nextBytePos := bytePos + cvLengths[i]*libunlynx.ByteArraySize

		cv := make(libunlynx.CipherVector, cvLengths[i])
		v := data[bytePos:nextBytePos]

		if libunlynx.PARALLELIZE {
			go func(v []byte, i int) {
				defer wg.Done()
				cv.FromBytes(v, cvLengths[i])
				(*sm).Data[i] = cv
			}(v, i)
		} else {
			cv.FromBytes(v, cvLengths[i])
			(*sm).Data[i] = cv
		}

		// advance pointer
		bytePos = nextBytePos
	}
	libunlynx.EndParallelize(wg)


	/*
	var nbrData int

	elementLength := (gacbLength*64 + aabLength*64 + pgaebLength*64) //CAUTION: hardcoded 64 (size of el-gamal element C,K)
	nbrData = len(data) / elementLength

	(*sm).Data = make([]libunlynx.CipherVector, nbrData)
	wg := libunlynx.StartParallelize(nbrData)
	for i := 0; i < nbrData; i++ {
		v := data[i*elementLength : i*elementLength+elementLength]
		if libunlynx.PARALLELIZE {
			go func(v []byte, i int) {
				defer wg.Done()
				(*sm).Data[i].FromBytes(v, gacbLength, aabLength, pgaebLength)
			}(v, i)
		} else {
			(*sm).Data[i].FromBytes(v, gacbLength, aabLength, pgaebLength)
		}
	}
	libunlynx.EndParallelize(wg)
	*/
}

