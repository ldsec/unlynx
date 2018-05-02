// Package protocolsunlynx contains the distributed deterministic tagging protocol which permits to add a deterministic
// tag to a DP response.
// The El-Gamal encrypted DP response should be encrypted by the collective public key of the cothority.
// In that case, each cothority server (node) can remove his El-Gamal secret contribution and homomorphically
// multiply the ciphertext to participate in the tag creation.
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
	"github.com/lca1/unlynx/lib/proofs"
	"sync"
	"time"
)

// DeterministicTaggingProtocolName is the registered name for the deterministic tagging protocol.
const DeterministicTaggingProtocolName = "DeterministicTagging"

func init() {
	network.RegisterMessage(DeterministicTaggingMessage{})
	network.RegisterMessage(DeterministicTaggingBytesMessage{})
	network.RegisterMessage(DTBLengthMessage{})
	network.RegisterMessage(libunlynx.ProcessResponseDet{})
	onet.GlobalProtocolRegister(DeterministicTaggingProtocolName, NewDeterministicTaggingProtocol)
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

	sendingDet(*p, DeterministicTaggingMessage{detTarget})

	return nil
}

// Dispatch is called on each tree node. It waits for incoming messages and handles them.
func (p *DeterministicTaggingProtocol) Dispatch() error {
	//************ ----- first round, add value derivated from ephemeral secret to message ---- ********************
	deterministicTaggingTargetBytesBef := <-p.PreviousNodeInPathChannel
	deterministicTaggingTargetBef := DeterministicTaggingMessage{Data: make([]libunlynx.CipherText, 0)}
	deterministicTaggingTargetBef.FromBytes(deterministicTaggingTargetBytesBef.Data)

	startT := time.Now()
	toAdd := libunlynx.SuiTe.Point().Mul(*p.SurveySecretKey, libunlynx.SuiTe.Point().Base())
	if libunlynx.PARALLELIZE {
		var wg sync.WaitGroup
		for i := 0; i < len(deterministicTaggingTargetBef.Data); i += libunlynx.VPARALLELIZE {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				for j := 0; j < libunlynx.VPARALLELIZE && (i+j) < len(deterministicTaggingTargetBef.Data); j++ {
					tmp := libunlynx.SuiTe.Point().Add(deterministicTaggingTargetBef.Data[i+j].C, toAdd)
					if p.Proofs {
						prf := libunlynxproofs.DetTagAdditionProofCreation(deterministicTaggingTargetBef.Data[i+j].C,
							*p.SurveySecretKey, toAdd, tmp)
						//TODO: proof publication
						_ = prf
					}
					deterministicTaggingTargetBef.Data[i+j].C = tmp
				}
			}(i)
		}
		wg.Wait()
	} else {
		for i, v := range deterministicTaggingTargetBef.Data {
			tmp := libunlynx.SuiTe.Point().Add(v.C, toAdd)
			if p.Proofs {
				prf := libunlynxproofs.DetTagAdditionProofCreation(v.C, *p.SurveySecretKey, toAdd, tmp)
				_ = prf
			}
			deterministicTaggingTargetBef.Data[i].C = tmp
		}
	}
	log.Lvl1(p.ServerIdentity(), " preparation round for deterministic tagging")

	if p.IsRoot() {
		p.ExecTime += time.Since(startT)
	}
	sendingDet(*p, deterministicTaggingTargetBef)

	//************ ----- second round, deterministic tag creation  ---- ********************
	deterministicTaggingTargetBytes := <-p.PreviousNodeInPathChannel
	deterministicTaggingTarget := DeterministicTaggingMessage{Data: make([]libunlynx.CipherText, 0)}
	deterministicTaggingTarget.FromBytes(deterministicTaggingTargetBytes.Data)

	startT = time.Now()
	roundTotalComputation := libunlynx.StartTimer(p.Name() + "_DetTagging(DISPATCH)")

	if libunlynx.PARALLELIZE {
		var wg sync.WaitGroup
		for i := 0; i < len(deterministicTaggingTarget.Data); i += libunlynx.VPARALLELIZE {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				j := i + libunlynx.VPARALLELIZE
				if j > len(deterministicTaggingTarget.Data) {
					j = len(deterministicTaggingTarget.Data)
				}
				tmp := deterministicTaggingTarget.Data[i:j]
				TaggingDet(&tmp, p.Private(), *p.SurveySecretKey, p.Public(), p.Proofs)
				copy(deterministicTaggingTarget.Data[i:j], tmp)
			}(i)
		}
		wg.Wait()
	} else {
		TaggingDet(&deterministicTaggingTarget.Data, p.Private(), *p.SurveySecretKey, p.Public(), p.Proofs)
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
		// Forward switched message.
		sendingDet(*p, deterministicTaggingTarget)
	}

	return nil
}

// sendToNext sends the message msg to the next node in the circuit based on the next TreeNode in Tree.List() If not visited yet.
// If the message already visited the next node, doesn't send and returns false. Otherwise, return true.
func (p *DeterministicTaggingProtocol) sendToNext(msg interface{}) {
	err := p.SendTo(p.nextNodeInCircuit, msg)
	if err != nil {
		log.Lvl1("Had an error sending a message: ", err)
	}
}

// sendingDet sends DeterministicTaggingBytes messages
func sendingDet(p DeterministicTaggingProtocol, detTarget DeterministicTaggingMessage) {
	data := detTarget.ToBytes()
	p.sendToNext(&DeterministicTaggingBytesMessage{Data: data})
}

// TaggingDet performs one step in the distributed deterministic tagging process and creates corresponding proof
func TaggingDet(cv *libunlynx.CipherVector, privKey, secretContrib kyber.Scalar, pubKey kyber.Point, proofs bool) {
	switchedVect := libunlynx.NewCipherVector(len(*cv))
	switchedVect.DeterministicTagging(cv, privKey, secretContrib)

	if proofs {
		p1 := libunlynxproofs.VectorDeterministicTagProofCreation(*cv, *switchedVect, secretContrib, privKey)
		//proof publication
		commitSecret := libunlynx.SuiTe.Point().Mul(secretContrib, libunlynx.SuiTe.Point().Base())
		publishedProof := libunlynxproofs.PublishedDeterministicTaggingProof{Dhp: p1, VectBefore: *cv, VectAfter: *switchedVect, K: pubKey, SB: commitSecret}
		_ = publishedProof
	}

	*cv = *switchedVect
}

// CipherVectorToDeterministicTag creates a tag (grouping key) from a cipher vector
func CipherVectorToDeterministicTag(cipherVect libunlynx.CipherVector, privKey, secContrib kyber.Scalar, pubKey kyber.Point, proofs bool) libunlynx.GroupingKey {
	TaggingDet(&cipherVect, privKey, secContrib, pubKey, proofs)
	deterministicGroupAttributes := make(libunlynx.DeterministCipherVector, len(cipherVect))
	for j, c := range cipherVect {
		deterministicGroupAttributes[j] = libunlynx.DeterministCipherText{Point: c.C}
	}
	return deterministicGroupAttributes.Key()
}

// Conversion
//______________________________________________________________________________________________________________________

// ToBytes converts a DeterministicTaggingMessage to a byte array
func (dtm *DeterministicTaggingMessage) ToBytes() []byte {

	length := len((*dtm).Data)

	b := make([]byte, 0)
	bb := make([][]byte, length)

	var mutexD sync.Mutex
	if libunlynx.PARALLELIZE {
		var wg sync.WaitGroup
		for i := 0; i < length; i += libunlynx.VPARALLELIZE {
			wg.Add(1)
			go func(i int) {
				for j := 0; j < libunlynx.VPARALLELIZE && (i+j) < length; j++ {
					mutexD.Lock()
					data := (*dtm).Data[i+j]
					mutexD.Unlock()
					bb[i+j] = data.ToBytes()
				}
				defer wg.Done()
			}(i)
		}
		wg.Wait()
	} else {
		for i, v := range (*dtm).Data {
			bb[i] = v.ToBytes()
		}
	}

	for _, v := range bb {
		b = append(b, v...)
	}
	return b
}

// FromBytes converts a byte array to a DeterministicTaggingMessage. Note that you need to create the (empty) object beforehand.
func (dtm *DeterministicTaggingMessage) FromBytes(data []byte) {

	//cvLengths := UnsafeCastBytesToInts(cvLengthsByte)
	elementSize := libunlynx.CipherTextByteSize()
	(*dtm).Data = make([]libunlynx.CipherText, len(data)/elementSize)

	// iter over each value in the flatten data byte array
	if libunlynx.PARALLELIZE {
		var wg sync.WaitGroup
		for i := 0; i < len(data); i += elementSize * libunlynx.VPARALLELIZE {
			wg.Add(1)
			go func(i int) {
				for j := 0; j < elementSize*libunlynx.VPARALLELIZE && i+j < len(data); j += elementSize {
					tmp := make([]byte, elementSize)
					copy(tmp, data[i+j:i+j+elementSize])
					(*dtm).Data[(i+j)/elementSize].FromBytes(tmp)
				}
				defer wg.Done()
			}(i)
		}
		wg.Wait()
	} else {
		for i := 0; i < len(data); i += elementSize {
			tmp := make([]byte, elementSize)
			copy(tmp, data[i:i+elementSize])
			(*dtm).Data[i/elementSize].FromBytes(tmp)
		}
	}
}
