// Package protocols contains the distributed deterministic tagging protocol which permits to add a deterministic
// tag to a DP response.
// The El-Gamal encrypted DP response should be encrypted by the collective public key of the cothority.
// In that case, each cothority server (node) can remove his El-Gamal secret contribution and homomorphically
// multiply the ciphertext to participate in the tag creation.
// This is done by creating a circuit between the servers. The DP response is sent through this circuit and
// each server applies its transformation on it and forwards it to the next node in the circuit
// until it comes back to the server who started the protocol.
package protocols

import (
	"errors"

	"github.com/lca1/unlynx/lib"
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/dedis/onet.v1/network"
	"sync"
)

// DeterministicTaggingProtocolName is the registered name for the deterministic tagging protocol.
const DeterministicTaggingProtocolName = "DeterministicTagging"

func init() {
	network.RegisterMessage(DeterministicTaggingMessage{})
	network.RegisterMessage(DeterministicTaggingBytesMessage{})
	network.RegisterMessage(DTBLengthMessage{})
	network.RegisterMessage(lib.ProcessResponseDet{})
	onet.GlobalProtocolRegister(DeterministicTaggingProtocolName, NewDeterministicTaggingProtocol)
}

// Messages
//______________________________________________________________________________________________________________________

// GroupingAttributes are the grouping attributes used to create the tag
type GroupingAttributes struct {
	Vector lib.CipherVector
}

// DeterministicTaggingMessage represents a deterministic tagging message containing the processed cipher vectors DP
// responses.
type DeterministicTaggingMessage struct {
	Data []GroupingAttributes
}

// DeterministicTaggingBytesMessage represents a deterministic tagging message in bytes
type DeterministicTaggingBytesMessage struct {
	Data []byte
}

// DTBLengthMessage represents a message containing the length of a DeterministicTaggingMessageBytes message
type DTBLengthMessage struct {
	CVLength int
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
	FeedbackChannel chan []lib.ProcessResponseDet

	// Protocol communication channels
	PreviousNodeInPathChannel chan deterministicTaggingBytesStruct
	LengthNodeChannel         chan dtmbLengthStruct

	// Protocol state data
	nextNodeInCircuit *onet.TreeNode
	TargetOfSwitch    *[]lib.ProcessResponse
	SurveySecretKey   *abstract.Scalar
	Proofs            bool

	// Nbr of query attributes
	NbrQueryAttributes int
}

// NewDeterministicTaggingProtocol constructs tagging switching protocol instances.
func NewDeterministicTaggingProtocol(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	dsp := &DeterministicTaggingProtocol{
		TreeNodeInstance: n,
		FeedbackChannel:  make(chan []lib.ProcessResponseDet),
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

	roundTotalStart := lib.StartTimer(p.Name() + "_DetTagging(START)")

	if p.TargetOfSwitch == nil {
		return errors.New("No data on which to do a deterministic tagging")
	}
	if p.SurveySecretKey == nil {
		return errors.New("No survey secret key given")
	}

	nbrProcessResponses := len(*p.TargetOfSwitch)

	log.Lvl1("["+p.Name()+"]", " starts a Deterministic Tagging Protocol on ", nbrProcessResponses, " element(s)")

	// create process response with deterministic tag, at first step the tag creation part is a copy of the proba
	// grouping attributes
	detTarget := make([]GroupingAttributes, nbrProcessResponses)
	for i, v := range *p.TargetOfSwitch {
		detTarget[i].Vector = append(v.GroupByEnc, v.WhereEnc...)
	}
	lib.EndTimer(roundTotalStart)

	sendingDet(*p, DeterministicTaggingMessage{detTarget})

	return nil
}

// Dispatch is called on each tree node. It waits for incoming messages and handles them.
func (p *DeterministicTaggingProtocol) Dispatch() error {
	//************ ----- first round, add value derivated from ephemeral secret to message ---- ********************
	lengthBef := (<-p.LengthNodeChannel).CVLength
	deterministicTaggingTargetBytesBef := <-p.PreviousNodeInPathChannel
	deterministicTaggingTargetBef := DeterministicTaggingMessage{Data: make([]GroupingAttributes, 0)}
	deterministicTaggingTargetBef.FromBytes(deterministicTaggingTargetBytesBef.Data, lengthBef, p.NbrQueryAttributes)
	wg := lib.StartParallelize(len(deterministicTaggingTargetBef.Data))
	toAdd := network.Suite.Point().Mul(network.Suite.Point().Base(), *p.SurveySecretKey)
	for i := range deterministicTaggingTargetBef.Data {
		if lib.PARALLELIZE {
			go func(v []GroupingAttributes, i int) {
				defer wg.Done()
				for j := range v[i].Vector {
					tmp := network.Suite.Point().Add(v[i].Vector[j].C, toAdd)
					if p.Proofs {
						prf := lib.DetTagAdditionProofCreation(v[i].Vector[j].C, *p.SurveySecretKey, toAdd, tmp)
						//dummy proof publication
						_ = prf
					}
					v[i].Vector[j].C = tmp
				}

			}(deterministicTaggingTargetBef.Data, i)

		} else {
			for j := range deterministicTaggingTargetBef.Data[i].Vector {
				tmp := network.Suite.Point().Add(deterministicTaggingTargetBef.Data[i].Vector[j].C, toAdd)
				if p.Proofs {
					prf := lib.DetTagAdditionProofCreation(deterministicTaggingTargetBef.Data[i].Vector[j].C, *p.SurveySecretKey, toAdd, tmp)
					_ = prf
				}
				deterministicTaggingTargetBef.Data[i].Vector[j].C = tmp
			}
		}
	}

	lib.EndParallelize(wg)
	log.Lvl1(p.ServerIdentity(), " preparation round for deterministic tagging")

	sendingDet(*p, deterministicTaggingTargetBef)

	//************ ----- second round, deterministic tag creation  ---- ********************
	length := (<-p.LengthNodeChannel).CVLength
	deterministicTaggingTargetBytes := <-p.PreviousNodeInPathChannel
	deterministicTaggingTarget := DeterministicTaggingMessage{Data: make([]GroupingAttributes, 0)}
	deterministicTaggingTarget.FromBytes(deterministicTaggingTargetBytes.Data, length, p.NbrQueryAttributes)

	roundTotalComputation := lib.StartTimer(p.Name() + "_DetTagging(DISPATCH)")

	wg = lib.StartParallelize(len(deterministicTaggingTarget.Data))
	for i := range deterministicTaggingTarget.Data {
		if lib.PARALLELIZE {
			go func(v []GroupingAttributes, i int) {
				defer wg.Done()
				v[i].Vector.TaggingDet(p.Private(), *p.SurveySecretKey, p.Public(), p.Proofs)

			}(deterministicTaggingTarget.Data, i)

		} else {
			deterministicTaggingTarget.Data[i].Vector.TaggingDet(p.Private(), *p.SurveySecretKey, p.Public(), p.Proofs)
		}
	}

	lib.EndParallelize(wg)

	var TaggedData []lib.ProcessResponseDet

	if p.IsRoot() {
		detCreatedData := deterministicTaggingTarget.Data
		TaggedData = make([]lib.ProcessResponseDet, len(*p.TargetOfSwitch))

		wg1 := lib.StartParallelize(len(detCreatedData))
		for i, v := range detCreatedData {
			if lib.PARALLELIZE {
				go func(i int, v GroupingAttributes) {
					defer wg1.Done()
					TaggedData[i] = deterministicTagFormat(i, v, p.TargetOfSwitch)
				}(i, v)
			} else {
				TaggedData[i] = deterministicTagFormat(i, v, p.TargetOfSwitch)
			}

		}

		lib.EndParallelize(wg1)
		log.Lvl1(p.ServerIdentity(), " completed deterministic Tagging (", len(detCreatedData), "row )")
	} else {
		log.Lvl1(p.ServerIdentity(), " carried on deterministic Tagging.", len(deterministicTaggingTarget.Data))
	}

	lib.EndTimer(roundTotalComputation)

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
	data, cvLength := detTarget.ToBytes(p.NbrQueryAttributes)
	p.sendToNext(&DTBLengthMessage{CVLength: cvLength})
	p.sendToNext(&DeterministicTaggingBytesMessage{Data: data})
}

// DeterministicTagFormat creates a response with a deterministic tag
func deterministicTagFormat(i int, v GroupingAttributes, targetofSwitch *[]lib.ProcessResponse) lib.ProcessResponseDet {
	tmp := *targetofSwitch

	deterministicGroupAttributes := make(lib.DeterministCipherVector, len(tmp[i].GroupByEnc))
	deterministicWhereAttributes := make([]lib.GroupingKey, len(tmp[i].WhereEnc))
	for j, c := range v.Vector {
		if j < len(tmp[i].GroupByEnc) {
			deterministicGroupAttributes[j] = lib.DeterministCipherText{Point: c.C}
		} else if j < len(tmp[i].GroupByEnc)+len(tmp[i].WhereEnc) {
			tmp1 := (lib.DeterministCipherVector{lib.DeterministCipherText{Point: c.C}})
			deterministicWhereAttributes[j-len(tmp[i].GroupByEnc)] = tmp1.Key()
		}

	}
	return lib.ProcessResponseDet{PR: (*targetofSwitch)[i], DetTagGroupBy: deterministicGroupAttributes.Key(), DetTagWhere: deterministicWhereAttributes}
}

// Conversion
//______________________________________________________________________________________________________________________

// ToBytes converts a DeterministicTaggingMessage to a byte array
func (dtm *DeterministicTaggingMessage) ToBytes(nbrQueryAttributes int) ([]byte, int) {
	var cvLength int

	length := len((*dtm).Data)
	b := make([]byte, 0)
	bb := make([][]byte, length)

	wg := lib.StartParallelize(length)
	var mutexD sync.Mutex
	for i := range (*dtm).Data {
		if lib.PARALLELIZE {
			go func(i int) {
				defer wg.Done()

				mutexD.Lock()
				data := (*dtm).Data[i].Vector
				mutexD.Unlock()
				aux, cvAux := data.ToBytes()

				mutexD.Lock()
				bb[i] = aux
				if i >= nbrQueryAttributes {
					cvLength = cvAux
				}

				mutexD.Unlock()
			}(i)
		} else {
			if i > nbrQueryAttributes {
				bb[i], cvLength = (*dtm).Data[i].Vector.ToBytes()
			} else {
				bb[i], _ = (*dtm).Data[i].Vector.ToBytes()
			}

		}

	}
	lib.EndParallelize(wg)
	for _, v := range bb {
		b = append(b, v...)
	}
	return b, cvLength
}

// FromBytes converts a byte array to a DeterministicTaggingMessage. Note that you need to create the (empty) object beforehand.
func (dtm *DeterministicTaggingMessage) FromBytes(data []byte, cvLength int, nbrQueryAttributes int) {
	cvByteLength := (cvLength * 64) //TODO: hardcoded 64 (size of el-gamal element C,K)
	nbrQueryAttrBytes := nbrQueryAttributes * 64
	nbrGroupingAttributes := (len(data) - nbrQueryAttrBytes) / cvByteLength

	(*dtm).Data = make([]GroupingAttributes, nbrGroupingAttributes+nbrQueryAttributes)
	for i := 0; i < nbrQueryAttributes; i++ {
		cv := make(lib.CipherVector, 1)
		cv.FromBytes(data[i*64:i*64+64], 1)
		(*dtm).Data[i] = GroupingAttributes{cv}
	}
	data = data[nbrQueryAttrBytes:]

	wg := lib.StartParallelize(nbrGroupingAttributes)

	for i := nbrQueryAttributes; i < nbrQueryAttributes+nbrGroupingAttributes; i++ {
		v := data[(i-nbrQueryAttributes)*cvByteLength : (i-nbrQueryAttributes)*cvByteLength+cvByteLength]
		cv := make(lib.CipherVector, cvLength)
		if lib.PARALLELIZE {
			go func(v []byte, i int) {
				defer wg.Done()
				cv.FromBytes(v, cvLength)
				(*dtm).Data[i] = GroupingAttributes{cv}
			}(v, i)
		} else {
			cv.FromBytes(v, cvLength)
			(*dtm).Data[i] = GroupingAttributes{cv}
		}
	}
	lib.EndParallelize(wg)
}
