package protocolsunlynx

import (
	"errors"
	"sync"

	"github.com/lca1/unlynx/lib"
	"github.com/lca1/unlynx/lib/deterministic_tag"
	"github.com/lca1/unlynx/lib/shuffle"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
)

// ShufflingPlusDDTProtocolName is the registered name for the shuffling + .
const ShufflingPlusDDTProtocolName = "ShufflingPlusDDTProtocol"

func init() {
	network.RegisterMessage(ShufflingPlusDDTMessage{})
	network.RegisterMessage(ShufflingPlusDDTBytesMessage{})
	network.RegisterMessage(ShufflingPlusDDTBytesLength{})
	if _, err := onet.GlobalProtocolRegister(ShufflingPlusDDTProtocolName, NewShufflingPlusDDTProtocol); err != nil {
		log.Fatal("Failed to register the <ShufflingPlusDDTProtocol> protocol:", err)
	}
}

// Messages
//______________________________________________________________________________________________________________________

// ShufflingPlusDDTMessage represents a message containing data to shuffle and tag
type ShufflingPlusDDTMessage struct {
	Data     []libunlynx.CipherVector
	ShuffKey kyber.Point // the key to use for shuffling
}

// ShufflingPlusDDTBytesMessage represents a ShufflingPlusDDTMessage in bytes
type ShufflingPlusDDTBytesMessage struct {
	Data     []byte
	ShuffKey []byte
}

// ShufflingPlusDDTBytesLength is a message containing the lengths to read a ShufflingPlusDDTMessage in bytes
type ShufflingPlusDDTBytesLength struct {
	CVLengths []byte
}

// Structs
//______________________________________________________________________________________________________________________

// shufflingPlusDDTBytesStruct contains a ShufflingPlusDDTMessage in bytes
type shufflingPlusDDTBytesStruct struct {
	*onet.TreeNode
	ShufflingPlusDDTBytesMessage
}

// shufflingBytesLengthStruct contains the length of the message
type shufflingPlusDDTBytesLengthStruct struct {
	*onet.TreeNode
	ShufflingPlusDDTBytesLength
}

// Protocol
//______________________________________________________________________________________________________________________

// ShufflingPlusDDTProtocol hold the state of a shuffling+ddt protocol instance.
type ShufflingPlusDDTProtocol struct {
	*onet.TreeNodeInstance

	// Protocol feedback channel
	FeedbackChannel chan []libunlynx.DeterministCipherVector

	// Protocol communication channels
	LengthNodeChannel         chan shufflingPlusDDTBytesLengthStruct
	PreviousNodeInPathChannel chan shufflingPlusDDTBytesStruct

	// Protocol state data
	TargetData        *[]libunlynx.CipherVector
	SurveySecretKey   *kyber.Scalar
	Precomputed       []libunlynxshuffle.CipherVectorScalar
	nextNodeInCircuit *onet.TreeNode

	// Proofs
	Proofs bool
}

// NewShufflingPlusDDTProtocol constructs neff shuffle + ddt protocol instance.
func NewShufflingPlusDDTProtocol(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	pi := &ShufflingPlusDDTProtocol{
		TreeNodeInstance: n,
		FeedbackChannel:  make(chan []libunlynx.DeterministCipherVector),
	}

	if err := pi.RegisterChannel(&pi.PreviousNodeInPathChannel); err != nil {
		return nil, errors.New("couldn't register data reference channel: " + err.Error())
	}

	if err := pi.RegisterChannel(&pi.LengthNodeChannel); err != nil {
		return nil, errors.New("couldn't register data reference channel: " + err.Error())
	}

	// choose next node in circuit
	nodeList := n.Tree().List()
	for i, node := range nodeList {
		if n.TreeNode().Equal(node) {
			pi.nextNodeInCircuit = nodeList[(i+1)%len(nodeList)]
			break
		}
	}
	return pi, nil
}

// Start is called at the root node and starts the execution of the protocol.
func (p *ShufflingPlusDDTProtocol) Start() error {

	if p.TargetData == nil {
		return errors.New("no data is given")
	}
	nbrSqCVs := len(*p.TargetData)
	log.Lvl1("["+p.Name()+"]", " started a Shuffling+DDT Protocol (", nbrSqCVs, " responses)")

	shuffleTarget := *p.TargetData

	// STEP 4: Send to next node

	message := ShufflingPlusDDTBytesMessage{}
	var cvLengthsByte []byte

	message.Data, cvLengthsByte = (&ShufflingPlusDDTMessage{Data: shuffleTarget}).ToBytes()
	message.ShuffKey = libunlynx.AbstractPointsToBytes([]kyber.Point{p.Tree().Roster.Aggregate})

	p.sendToNext(&ShufflingPlusDDTBytesLength{CVLengths: cvLengthsByte})
	p.sendToNext(&message)

	return nil
}

// Dispatch is called on each tree node. It waits for incoming messages and handles them.
func (p *ShufflingPlusDDTProtocol) Dispatch() error {
	defer p.Done()

	shufflingPlusDDTBytesMessageLength := <-p.LengthNodeChannel
	tmp := <-p.PreviousNodeInPathChannel

	readData := libunlynx.StartTimer(p.Name() + "_ShufflingPlusDDT(ReadData)")
	sm := ShufflingPlusDDTMessage{}
	sm.FromBytes(tmp.Data, tmp.ShuffKey, shufflingPlusDDTBytesMessageLength.CVLengths)
	libunlynx.EndTimer(readData)

	// STEP 1: Shuffling of the data
	step1 := libunlynx.StartTimer(p.Name() + "_ShufflingPlusDDT(Step1-Shuffling)")
	if p.Precomputed != nil {
		log.Lvl1(p.Name(), " uses pre-computation in shuffling")
	}
	shuffledData, pi, beta := libunlynxshuffle.ShuffleSequence(sm.Data, libunlynx.SuiTe.Point().Base(), sm.ShuffKey, p.Precomputed)
	libunlynx.EndTimer(step1)

	if p.Proofs {
		libunlynxshuffle.ShuffleProofCreation(sm.Data, shuffledData, libunlynx.SuiTe.Point().Base(), sm.ShuffKey, beta, pi)
	}

	// STEP 2: Addition of secret (first round of DDT, add value derivated from ephemeral secret to message)
	step2 := libunlynx.StartTimer(p.Name() + "_ShufflingPlusDDT(Step2-DDTAddition)")
	toAdd := libunlynx.SuiTe.Point().Mul(*p.SurveySecretKey, libunlynx.SuiTe.Point().Base()) //siB (basically)
	wg := sync.WaitGroup{}
	for i := 0; i < len(shuffledData); i += libunlynx.VPARALLELIZE {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < libunlynx.VPARALLELIZE && (i+j) < len(shuffledData); j++ {
				for k := range shuffledData[i+j] {
					tmp := libunlynx.SuiTe.Point().Add(shuffledData[i+j][k].C, toAdd)
					if p.Proofs {
						libunlynxdetertag.DeterministicTagAdditionProofCreation(shuffledData[i+j][k].C, *p.SurveySecretKey, toAdd, tmp)
					}
					shuffledData[i+j][k].C = tmp
				}
			}
		}(i)
	}
	wg.Wait()
	libunlynx.EndTimer(step2)

	log.Lvl1(p.ServerIdentity(), " preparation round for deterministic tagging")

	// STEP 3: Partial Decryption (second round of DDT, deterministic tag creation)
	step3 := libunlynx.StartTimer(p.Name() + "_ShufflingPlusDDT(Step3-DDT)")
	wg = sync.WaitGroup{}
	for i := 0; i < len(shuffledData); i += libunlynx.VPARALLELIZE {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < libunlynx.VPARALLELIZE && (i+j) < len(shuffledData); j++ {
				tmp := shuffledData[i+j]
				switchedVect := libunlynxdetertag.DeterministicTagSequence(tmp, p.Private(), *p.SurveySecretKey)
				if p.Proofs {
					libunlynxdetertag.DeterministicTagCrListProofCreation(tmp, switchedVect, p.Public(), *p.SurveySecretKey, p.Private())
				}
				copy(shuffledData[i+j], switchedVect)
			}
		}(i)
	}
	wg.Wait()
	libunlynx.EndTimer(step3)

	var taggedData []libunlynx.DeterministCipherVector

	if p.IsRoot() {
		prepareResult := libunlynx.StartTimer(p.Name() + "_ShufflingPlusDDT(PrepareResult)")
		taggedData = make([]libunlynx.DeterministCipherVector, len(*p.TargetData))
		size := 0
		for i, v := range shuffledData {
			taggedData[i] = make(libunlynx.DeterministCipherVector, len(v))
			for j, el := range v {
				taggedData[i][j] = libunlynx.DeterministCipherText{Point: el.C}
				size++
			}
		}
		libunlynx.EndTimer(prepareResult)
		log.Lvl1(p.ServerIdentity(), " completed shuffling+DDT protocol (", size, "responses )")
	} else {
		log.Lvl1(p.ServerIdentity(), " carried on shuffling+DDT protocol")
	}

	// STEP 4: Send to next node

	// If this tree node is the root, then protocol reached the end.
	if p.IsRoot() {
		p.FeedbackChannel <- taggedData
	} else {
		sendData := libunlynx.StartTimer(p.Name() + "_ShufflingPlusDDT(SendData)")
		message := ShufflingPlusDDTBytesMessage{}
		var cvBytesLengths []byte
		message.Data, cvBytesLengths = (&ShufflingPlusDDTMessage{Data: shuffledData}).ToBytes()
		// we have to subtract the key p.Public to the shuffling key (we partially decrypt during tagging)
		message.ShuffKey = libunlynx.AbstractPointsToBytes([]kyber.Point{sm.ShuffKey.Sub(sm.ShuffKey, p.Public())})
		libunlynx.EndTimer(sendData)

		p.sendToNext(&ShufflingPlusDDTBytesLength{cvBytesLengths})
		p.sendToNext(&message)
	}

	return nil
}

// Sends the message msg to the next node in the circuit based on the next TreeNode in Tree.List().
func (p *ShufflingPlusDDTProtocol) sendToNext(msg interface{}) {
	err := p.SendTo(p.nextNodeInCircuit, msg)
	if err != nil {
		log.Fatal(err)
	}
}

// Marshal
//______________________________________________________________________________________________________________________

// ToBytes converts a ShufflingPlusDDTMessage to a byte array
func (spddtm *ShufflingPlusDDTMessage) ToBytes() ([]byte, []byte) {
	return libunlynx.ArrayCipherVectorToBytes(spddtm.Data)
}

// FromBytes converts a byte array to a ShufflingPlusDDTMessage. Note that you need to create the (empty) object beforehand.
func (spddtm *ShufflingPlusDDTMessage) FromBytes(data []byte, shuffKey []byte, cvLengthsByte []byte) {
	(*spddtm).Data = libunlynx.FromBytesToArrayCipherVector(data, cvLengthsByte)
	(*spddtm).ShuffKey = libunlynx.FromBytesToAbstractPoints(shuffKey)[0]
}
