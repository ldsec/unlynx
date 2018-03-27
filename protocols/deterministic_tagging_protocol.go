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
	"reflect"
	"sync"
	"time"
	"unsafe"
	"math"
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
	Data []libunlynx.CipherText
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
	TargetOfSwitch    *[]libunlynx.CipherText
	SurveySecretKey   *kyber.Scalar
	Proofs            bool

	ExecTime time.Duration
}

func ProcessResponseToCipherTextArray(p []libunlynx.ProcessResponse) ([]libunlynx.CipherText, [][]int) {
	cipherTexts := make([]libunlynx.CipherText, 0)
	lengths := make([][]int, len(p))

	for i, v := range p {
		lengths[i] = make([]int, 4)
		cipherTexts = append(cipherTexts, v.WhereEnc...)
		lengths[i][0] = len(v.WhereEnc)
		cipherTexts = append(cipherTexts, v.GroupByEnc...)
		lengths[i][1] = len(v.GroupByEnc)
		cipherTexts = append(cipherTexts, v.AggregatingAttributes...)
		lengths[i][2] = len(v.AggregatingAttributes)
	}

	return cipherTexts, lengths
}

func CipherTextArrayToProcessResponse(ct []libunlynx.CipherText, lengths [][]int) []libunlynx.ProcessResponse {
	result := make([]libunlynx.ProcessResponse, len(lengths))

	pos := 0
	for i, v := range result {
		v.WhereEnc = make(libunlynx.CipherVector, lengths[i][0])
		copy(v.WhereEnc, ct[pos : pos+lengths[i][0]])
		pos += lengths[i][0]
		v.GroupByEnc = make(libunlynx.CipherVector, lengths[i][1])
		copy(v.GroupByEnc, ct[pos : pos+lengths[i][1]])
		pos += lengths[i][1]
		v.AggregatingAttributes = make(libunlynx.CipherVector, lengths[i][2])
		copy(v.WhereEnc, ct[pos : pos+lengths[i][2]])
		pos += lengths[i][2]
	}

	return result
}

func DetCipherTextToProcessResponseDet(detCt libunlynx.DeterministCipherVector, length [][]int,
	targetOfSwitch []libunlynx.ProcessResponse) []libunlynx.ProcessResponseDet {
	result := make([]libunlynx.ProcessResponseDet, len(length))

	pos := 0
	for i := range result {
		deterministicGroupAttributes := make(libunlynx.DeterministCipherVector, length[i][0])
		copy(deterministicGroupAttributes, detCt[pos : pos+length[i][0]])
		pos += length[i][0]

		deterministicWhereAttributes := make([]libunlynx.GroupingKey, length[i][1])
		for j, c := range detCt[pos : pos+length[i][1]] {
			deterministicWhereAttributes[j] = libunlynx.GroupingKey(c.String())
		}

		result = append(result,
			libunlynx.ProcessResponseDet{PR: targetOfSwitch[i], DetTagGroupBy: deterministicGroupAttributes.Key(),
			DetTagWhere: deterministicWhereAttributes} )

		pos += length[i][1] + length[i][2]
	}

	return result
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

	nbrProcessResponses := len(*p.TargetOfSwitch)

	log.Lvl1("["+p.Name()+"]", " starts a Deterministic Tagging Protocol on ", nbrProcessResponses, " element(s)")

	// create process response with deterministic tag, at first step the tag creation part is a copy of the proba
	// grouping attributes
	detTarget := make([]libunlynx.CipherText, len(*p.TargetOfSwitch))
	copy(detTarget, *p.TargetOfSwitch)
	libunlynx.EndTimer(roundTotalStart)

	sendingDet(*p, DeterministicTaggingMessage{detTarget})

	return nil
}

// Dispatch is called on each tree node. It waits for incoming messages and handles them.
func (p *DeterministicTaggingProtocol) Dispatch() error {
	//************ ----- first round, add value derivated from ephemeral secret to message ---- ********************
	//lengthBef := <-p.LengthNodeChannel
	deterministicTaggingTargetBytesBef := <-p.PreviousNodeInPathChannel
	deterministicTaggingTargetBef := DeterministicTaggingMessage{Data: make([]libunlynx.CipherText, 0)}
	deterministicTaggingTargetBef.FromBytes(deterministicTaggingTargetBytesBef.Data)

	startT := time.Now()
	//:= libunlynx.StartParallelize(len(deterministicTaggingTargetBef.Data))
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
						prf := libunlynx.DetTagAdditionProofCreation(deterministicTaggingTargetBef.Data[i+j].C,
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
				prf := libunlynx.DetTagAdditionProofCreation(v.C, *p.SurveySecretKey, toAdd, tmp)
				_ = prf
			}
			deterministicTaggingTargetBef.Data[i].C = tmp
		}
	}
	/*
	*/
	log.Lvl1(p.ServerIdentity(), " preparation round for deterministic tagging")

	if p.IsRoot() {
		p.ExecTime += time.Since(startT)
	}
	sendingDet(*p, deterministicTaggingTargetBef)

	//************ ----- second round, deterministic tag creation  ---- ********************
	//length := <-p.LengthNodeChannel
	deterministicTaggingTargetBytes := <-p.PreviousNodeInPathChannel
	deterministicTaggingTarget := DeterministicTaggingMessage{Data: make([]libunlynx.CipherText, 0)}
	deterministicTaggingTarget.FromBytes(deterministicTaggingTargetBytes.Data)

	startT = time.Now()
	roundTotalComputation := libunlynx.StartTimer(p.Name() + "_DetTagging(DISPATCH)")

	if libunlynx.PARALLELIZE {
		var wg sync.WaitGroup
		for i := 0; i < len(deterministicTaggingTarget.Data); i += libunlynx.VPARALLELIZE {
			go func(i int) {
				defer wg.Done()
				j := int(math.Max(float64(i + libunlynx.VPARALLELIZE), float64(len(deterministicTaggingTarget.Data))))
				tmp := make(libunlynx.CipherVector, j - i)
				copy(tmp, deterministicTaggingTarget.Data[i:j])
				tmp.TaggingDet(p.Private(), *p.SurveySecretKey, p.Public(), p.Proofs)
			}(i)
		}
	} else {
		tmp := libunlynx.CipherVector(deterministicTaggingTarget.Data)
		tmp.TaggingDet(p.Private(), *p.SurveySecretKey, p.Public(), p.Proofs)
	}

	var TaggedData []libunlynx.DeterministCipherText

	if p.IsRoot() {
		detCreatedData := deterministicTaggingTarget.Data
		TaggedData = make([]libunlynx.DeterministCipherText, len(*p.TargetOfSwitch))

		for i, v := range detCreatedData {
			TaggedData[i] = libunlynx.DeterministCipherText{Point: v.C}
		}

		/**
		wg1 := libunlynx.StartParallelize(len(detCreatedData))
		for i, v := range detCreatedData {
			tmp := make([]libunlynx.CipherText, 1)
			tmp[0] = v
			if libunlynx.PARALLELIZE {
				go func(i int, v libunlynx.CipherText) {
					defer wg1.Done()
					TaggedData[i] = *deterministicTagFormat(i, libunlynx.CipherVector(tmp), p.TargetOfSwitch)
				}(i, v)
			} else {
				TaggedData[i] = *deterministicTagFormat(i, libunlynx.CipherVector(tmp), p.TargetOfSwitch)
			}

		}
		libunlynx.EndParallelize(wg1)
		**/

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

/*
// DeterministicTagFormat creates a response with a deterministic tag
func deterministicTagFormat(i int, v libunlynx.CipherVector, targetofSwitch *[]libunlynx.CipherText) *libunlynx.ProcessResponseDet {
	tmp := *targetofSwitch

	result := make([]libunlynx.DeterministCipherText, len(tmp))
	for j, c := range tmp {

	}

	deterministicGroupAttributes := make(libunlynx.DeterministCipherVector, len(tmp[i].GroupByEnc))
	deterministicWhereAttributes := make([]libunlynx.GroupingKey, len(tmp[i].WhereEnc))
	for j, c := range v {
		if j < len(tmp[i].GroupByEnc) {
			deterministicGroupAttributes[j] = libunlynx.DeterministCipherText{Point: c.C}
		} else if j < len(tmp[i].GroupByEnc)+len(tmp[i].WhereEnc) {
			tmp1 := libunlynx.DeterministCipherVector{libunlynx.DeterministCipherText{Point: c.C}}
			deterministicWhereAttributes[j-len(tmp[i].GroupByEnc)] = tmp1.Key()
		}

	}
	return &libunlynx.ProcessResponseDet{PR: (*targetofSwitch)[i], DetTagGroupBy: deterministicGroupAttributes.Key(), DetTagWhere: deterministicWhereAttributes}
}
*/

// Conversion
//______________________________________________________________________________________________________________________

// cast using reflect []int <-> []byte
// from http://stackoverflow.com/questions/17539001/converting-int32-to-byte-array-in-go

// IntByteSize is the byte size of an int in memory
const IntByteSize = int(unsafe.Sizeof(int(0)))

// UnsafeCastIntsToBytes casts a slice of ints to a slice of bytes
func UnsafeCastIntsToBytes(ints []int) []byte {
	length := len(ints) * IntByteSize
	hdr := reflect.SliceHeader{Data: uintptr(unsafe.Pointer(&ints[0])), Len: length, Cap: length}
	return *(*[]byte)(unsafe.Pointer(&hdr))
}

// UnsafeCastBytesToInts casts a slice of bytes to a slice of ints
func UnsafeCastBytesToInts(bytes []byte) []int {
	length := len(bytes) / IntByteSize
	hdr := reflect.SliceHeader{Data: uintptr(unsafe.Pointer(&bytes[0])), Len: length, Cap: length}
	return *(*[]int)(unsafe.Pointer(&hdr))
}

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
					bb[i] = data.ToBytes()
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
func (dtm *DeterministicTaggingMessage) FromBytes (data []byte)  {

	//cvLengths := UnsafeCastBytesToInts(cvLengthsByte)
	(*dtm).Data = make([]libunlynx.CipherText, len(data) / libunlynx.ByteArraySize)

	// iter over each value in the flatten data byte array
	if libunlynx.PARALLELIZE {
		var wg sync.WaitGroup
		for i := 0; i < len(data); i += libunlynx.ByteArraySize * libunlynx.VPARALLELIZE {
			wg.Add(1)
			go func(i int) {
				for j := 0; j < libunlynx.ByteArraySize*libunlynx.VPARALLELIZE && i+j < len(data); j += libunlynx.ByteArraySize {
					tmp := make([]byte, libunlynx.ByteArraySize)
					copy(tmp, data[i+j:i+j+libunlynx.ByteArraySize])
					(*dtm).Data[(i+j)/libunlynx.ByteArraySize].FromBytes(tmp)
				}
				defer wg.Done()
			}(i)
		}
		wg.Wait()
	} else {
		for i := 0; i < len(data); i += libunlynx.ByteArraySize {
			tmp := make([]byte, libunlynx.ByteArraySize)
			copy(tmp, data[i:i+libunlynx.ByteArraySize])
			(*dtm).Data[i/libunlynx.ByteArraySize].FromBytes(tmp)
		}
	}
}
