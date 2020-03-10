// Package protocolsunlynx implement the distributed deterministic tagging protocol, that deterministically tags ciphertexts.
// In other words, the probabilistic ciphertexts are converted to a deterministic tag (identifier).
// To do this each cothority server (node) removes its secret contribution and homomorphically multiplies
// the ciphertexts with an ephemeral secret.
// This protocol operates in a circuit between the servers: the data is sent sequentially through this circuit and each
// server applies its transformation.
package protocolsunlynx

import (
	"errors"
	"sync"
	"time"

	"github.com/ldsec/unlynx/lib"
	"github.com/ldsec/unlynx/lib/deterministic_tag"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
)

// DeterministicTaggingProtocolName is the registered name for the deterministic tagging protocol.
const DeterministicTaggingProtocolName = "DeterministicTagging"

func init() {
	network.RegisterMessage(DeterministicTaggingMessage{})
	network.RegisterMessage(DeterministicTaggingBytesMessage{})
	network.RegisterMessage(DTBLengthMessage{})
	network.RegisterMessage(libunlynx.ProcessResponseDet{})
	_, err := onet.GlobalProtocolRegister(DeterministicTaggingProtocolName, NewDeterministicTaggingProtocol)
	log.ErrFatal(err, "Failed to register the <DeterministicTagging> protocol:")
}

// Messages
//______________________________________________________________________________________________________________________

// GroupingAttributes are the grouping attributes used to create the tag
type GroupingAttributes struct {
	Vector libunlynx.CipherVector
}

// DeterministicTaggingMessage represents a deterministic tagging message containing the processed cipher vectors DP
// responses.
type DeterministicTaggingMessage struct {
	Data libunlynx.CipherVector
}

// DeterministicTaggingBytesMessage represents a deterministic tagging message in bytes
type DeterministicTaggingBytesMessage struct {
	Data []byte
}

// DTBLengthMessage represents a message containing the lengths of a DeterministicTaggingMessageBytes message
type DTBLengthMessage struct {
	CVLengths []byte
}

// Structs
//______________________________________________________________________________________________________________________

// deterministicTaggingStructBytes is a deterministicTaggingStruct in bytes
type deterministicTaggingBytesStruct struct {
	*onet.TreeNode
	DeterministicTaggingBytesMessage
}

// dtmbLengthStruct is a structure containing a message for message length
type dtmbLengthStruct struct {
	*onet.TreeNode
	DTBLengthMessage
}

// Protocol
//______________________________________________________________________________________________________________________

// DeterministicTaggingProtocol hold the state of a deterministic tagging protocol instance.
type DeterministicTaggingProtocol struct {
	*onet.TreeNodeInstance

	// Protocol feedback channel
	FeedbackChannel chan []libunlynx.DeterministCipherText

	// Protocol communication channels
	PreviousNodeInPathChannel chan deterministicTaggingBytesStruct
	LengthNodeChannel         chan dtmbLengthStruct

	// Protocol state data
	nextNodeInCircuit *onet.TreeNode
	TargetOfSwitch    *libunlynx.CipherVector
	SurveySecretKey   *kyber.Scalar
	Proofs            bool

	ExecTime time.Duration

	Timeout time.Duration
}

// NewDeterministicTaggingProtocol constructs tagging switching protocol instances.
func NewDeterministicTaggingProtocol(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	dsp := &DeterministicTaggingProtocol{
		TreeNodeInstance: n,
		FeedbackChannel:  make(chan []libunlynx.DeterministCipherText),
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

	// default timeout
	dsp.Timeout = 10 * time.Minute

	return dsp, nil
}

// Start is called at the root node and starts the execution of the protocol.
func (p *DeterministicTaggingProtocol) Start() error {

	roundTotalStart := libunlynx.StartTimer(p.Name() + "_DetTagging(START)")

	if p.TargetOfSwitch == nil {
		return errors.New("no data on which to do a deterministic tagging")
	}
	if p.SurveySecretKey == nil {
		return errors.New("no survey secret key given")
	}

	p.ExecTime = 0

	nbrCipherText := len(*p.TargetOfSwitch)

	log.Lvl1("["+p.Name()+"]", " starts a Deterministic Tagging Protocol on ", nbrCipherText, " element(s)")

	// create CipherVector with deterministic tag, at first step the tag creation part is a copy of the proba
	detTarget := make(libunlynx.CipherVector, nbrCipherText)
	copy(detTarget, *p.TargetOfSwitch)
	libunlynx.EndTimer(roundTotalStart)

	err := sendingDet(*p, DeterministicTaggingMessage{detTarget})
	if err != nil {
		return err
	}

	return nil
}

// Dispatch is called on each tree node. It waits for incoming messages and handles them.
func (p *DeterministicTaggingProtocol) Dispatch() error {
	defer p.Done()

	//************ ----- first round, add value derivated from ephemeral secret to message ---- ********************
	var deterministicTaggingTargetBytesBef deterministicTaggingBytesStruct
	select {
	case deterministicTaggingTargetBytesBef = <-p.PreviousNodeInPathChannel:
		break
	case <-time.After(p.Timeout):
		return errors.New(p.ServerIdentity().String() + "didn't get the <deterministicTaggingTargetBytesBef> (first round) on time.")
	}

	deterministicTaggingTargetBef := DeterministicTaggingMessage{Data: make([]libunlynx.CipherText, 0)}
	err := deterministicTaggingTargetBef.FromBytes(deterministicTaggingTargetBytesBef.Data)
	if err != nil {
		return err
	}

	startT := time.Now()
	toAdd := libunlynx.SuiTe.Point().Mul(*p.SurveySecretKey, libunlynx.SuiTe.Point().Base())

	mutex := sync.Mutex{}
	wg := sync.WaitGroup{}
	for i := 0; i < len(deterministicTaggingTargetBef.Data); i += libunlynx.VPARALLELIZE {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < libunlynx.VPARALLELIZE && (i+j) < len(deterministicTaggingTargetBef.Data); j++ {
				tmp := libunlynx.SuiTe.Point().Add(deterministicTaggingTargetBef.Data[i+j].C, toAdd)
				if p.Proofs {
					_, tmpErr := libunlynxdetertag.DeterministicTagAdditionProofCreation(deterministicTaggingTargetBef.Data[i+j].C, *p.SurveySecretKey, toAdd, tmp)
					if tmpErr != nil {
						mutex.Lock()
						err = tmpErr
						mutex.Unlock()
						return
					}
				}
				deterministicTaggingTargetBef.Data[i+j].C = tmp
			}
		}(i)
	}
	wg.Wait()
	if err != nil {
		return err
	}

	log.Lvl1(p.ServerIdentity(), " preparation round for deterministic tagging")

	if p.IsRoot() {
		p.ExecTime += time.Since(startT)
	}
	err = sendingDet(*p, deterministicTaggingTargetBef)
	if err != nil {
		return err
	}

	//************ ----- second round, deterministic tag creation  ---- ********************
	var deterministicTaggingTargetBytes deterministicTaggingBytesStruct
	select {
	case deterministicTaggingTargetBytes = <-p.PreviousNodeInPathChannel:
		break
	case <-time.After(p.Timeout):
		return errors.New(p.ServerIdentity().String() + "didn't get the <deterministicTaggingTargetBytes> (second round) on time.")
	}

	deterministicTaggingTarget := DeterministicTaggingMessage{Data: make([]libunlynx.CipherText, 0)}
	err = deterministicTaggingTarget.FromBytes(deterministicTaggingTargetBytes.Data)
	if err != nil {
		return err
	}

	startT = time.Now()
	roundTotalComputation := libunlynx.StartTimer(p.Name() + "_DetTagging(DISPATCH)")

	wg = sync.WaitGroup{}
	for i := 0; i < len(deterministicTaggingTarget.Data); i += libunlynx.VPARALLELIZE {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			j := i + libunlynx.VPARALLELIZE
			if j > len(deterministicTaggingTarget.Data) {
				j = len(deterministicTaggingTarget.Data)
			}
			tmp := deterministicTaggingTarget.Data[i:j]
			tmpErr := TaggingDet(&tmp, p.Private(), *p.SurveySecretKey, p.Public(), p.Proofs)
			if tmpErr != nil {
				mutex.Lock()
				err = tmpErr
				mutex.Unlock()
				return
			}
			copy(deterministicTaggingTarget.Data[i:j], tmp)
		}(i)
	}
	wg.Wait()
	if err != nil {
		return err
	}

	var TaggedData []libunlynx.DeterministCipherText

	if p.IsRoot() {
		detCreatedData := deterministicTaggingTarget.Data
		TaggedData = make(libunlynx.DeterministCipherVector, len(*p.TargetOfSwitch))

		for i, v := range detCreatedData {
			TaggedData[i] = libunlynx.DeterministCipherText{Point: v.C}
		}

		log.Lvl1(p.ServerIdentity(), " completed deterministic Tagging (", len(detCreatedData), "row )")
	} else {
		log.Lvl1(p.ServerIdentity(), " carried on deterministic Tagging.", len(deterministicTaggingTarget.Data))
	}

	libunlynx.EndTimer(roundTotalComputation)

	if p.IsRoot() {
		p.ExecTime += time.Since(startT)
	}

	// If this tree node is the root, then protocol reached the end.
	if p.IsRoot() {
		p.FeedbackChannel <- TaggedData
	} else {
		err := sendingDet(*p, deterministicTaggingTarget)
		if err != nil {
			return err
		}
	}

	return nil
}

// sendToNext sends the message msg to the next node in the circuit based on the next TreeNode in Tree.List() If not visited yet.
// If the message already visited the next node, doesn't send and returns false. Otherwise, return true.
func (p *DeterministicTaggingProtocol) sendToNext(msg interface{}) error {
	err := p.SendTo(p.nextNodeInCircuit, msg)
	if err != nil {
		return err
	}
	return nil
}

// sendingDet sends DeterministicTaggingBytes messages
func sendingDet(p DeterministicTaggingProtocol, detTarget DeterministicTaggingMessage) error {
	data, err := detTarget.ToBytes()
	if err != nil {
		return err
	}
	err = p.sendToNext(&DeterministicTaggingBytesMessage{Data: data})
	if err != nil {
		return err
	}
	return nil
}

// TaggingDet performs one step in the distributed deterministic tagging process and creates corresponding proof
func TaggingDet(cv *libunlynx.CipherVector, privKey, secretContrib kyber.Scalar, pubKey kyber.Point, proofs bool) error {
	switchedVect := libunlynxdetertag.DeterministicTagSequence(*cv, privKey, secretContrib)
	if proofs {
		_, err := libunlynxdetertag.DeterministicTagCrListProofCreation(*cv, switchedVect, pubKey, secretContrib, privKey)
		if err != nil {
			return err
		}
	}
	*cv = switchedVect
	return nil
}

// CipherVectorToDeterministicTag creates a tag (grouping key) from a cipher vector
func CipherVectorToDeterministicTag(cipherVect libunlynx.CipherVector, privKey, secContrib kyber.Scalar, pubKey kyber.Point, proofs bool) (libunlynx.GroupingKey, error) {
	err := TaggingDet(&cipherVect, privKey, secContrib, pubKey, proofs)
	if err != nil {
		return libunlynx.GroupingKey(""), err
	}
	deterministicGroupAttributes := make(libunlynx.DeterministCipherVector, len(cipherVect))
	for j, c := range cipherVect {
		deterministicGroupAttributes[j] = libunlynx.DeterministCipherText{Point: c.C}
	}
	return deterministicGroupAttributes.Key(), nil
}

// Conversion
//______________________________________________________________________________________________________________________

// ToBytes converts a DeterministicTaggingMessage to a byte array
func (dtm *DeterministicTaggingMessage) ToBytes() ([]byte, error) {

	length := len((*dtm).Data)

	b := make([]byte, 0)
	bb := make([][]byte, length)

	var mutexD sync.Mutex
	var err error

	var wg sync.WaitGroup
	for i := 0; i < length; i += libunlynx.VPARALLELIZE {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < libunlynx.VPARALLELIZE && (i+j) < length; j++ {
				var tmpErr error

				mutexD.Lock()
				data := (*dtm).Data[i+j]
				mutexD.Unlock()
				bb[i+j], tmpErr = data.ToBytes()
				if tmpErr != nil {
					mutexD.Lock()
					err = tmpErr
					mutexD.Unlock()
					return
				}

			}
		}(i)
	}
	wg.Wait()

	if err != nil {
		return nil, err
	}

	for _, v := range bb {
		b = append(b, v...)
	}
	return b, nil
}

// FromBytes converts a byte array to a DeterministicTaggingMessage. Note that you need to create the (empty) object beforehand.
func (dtm *DeterministicTaggingMessage) FromBytes(data []byte) error {
	elementSize := libunlynx.CipherTextByteSize()
	(*dtm).Data = make([]libunlynx.CipherText, len(data)/elementSize)

	// iter over each value in the flatten data byte array
	var err error
	mutex := sync.Mutex{}
	var wg sync.WaitGroup
	for i := 0; i < len(data); i += elementSize * libunlynx.VPARALLELIZE {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < elementSize*libunlynx.VPARALLELIZE && i+j < len(data); j += elementSize {
				tmp := make([]byte, elementSize)
				copy(tmp, data[i+j:i+j+elementSize])
				tmpErr := (*dtm).Data[(i+j)/elementSize].FromBytes(tmp)
				if tmpErr != nil {
					mutex.Lock()
					err = tmpErr
					mutex.Unlock()
					return
				}
			}
		}(i)
	}
	wg.Wait()

	if err != nil {
		return err
	}
	return nil
}
