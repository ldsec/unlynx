// Package protocolsunlynx contains the key switching protocol which permits to switch a ciphertext
// encrypted under a specific key by using an El-Gamal encryption (probabilistic) to a ciphertext encrypted
// under another key.
// The El-Gamal ciphertext should be encrypted by the collective public key of the cothority. In that case,
// each cothority server (node) can remove his El-Gamal secret contribution and add a new
// secret contribution containing the new key. By doing that the ciphertext is never decrypted.
// This is done by creating a circuit between the servers. The ciphertext is sent through this circuit and
// each server applies its transformation on the ciphertext and forwards it to the next node in the circuit
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
	"github.com/lca1/unlynx/lib/proofs"
)

// KeySwitchingProtocolName is the registered name for the key switching protocol.
const KeySwitchingProtocolName = "KeySwitching"

func init() {
	network.RegisterMessage(KeySwitchedCipherMessage{})
	network.RegisterMessage(KeySwitchedCipherBytesMessage{})
	network.RegisterMessage(KSCBLengthMessage{})
	onet.GlobalProtocolRegister(KeySwitchingProtocolName, NewKeySwitchingProtocol)
}

// Messages
//______________________________________________________________________________________________________________________

// OriginalEphemeralKeys represents the original ephemeral keys which are needed for the servers to be able to remove
// their secret contribution
type OriginalEphemeralKeys struct {
	GroupOriginalKeys []kyber.Point
	AttrOriginalKeys  []kyber.Point
}

// DataAndOriginalEphemeralKeys contains data being switched and the original ephemeral key needed at each step
type DataAndOriginalEphemeralKeys struct {
	Response				libunlynx.CipherText
	OriginalEphemeralKey	kyber.Point
}

// KeySwitchedCipherMessage contains cipherVector under switching.
type KeySwitchedCipherMessage struct {
	DataKey []DataAndOriginalEphemeralKeys
	NewKey  kyber.Point
}

// KeySwitchedCipherBytesMessage is the KeySwitchedCipherMessage in bytes.
type KeySwitchedCipherBytesMessage struct {
	Data []byte
}

// KSCBLengthMessage represents a message containing the lengths needed to read the KeySwitchedCipherBytesMessage
type KSCBLengthMessage struct {
	LenB int
}

// Structs
//______________________________________________________________________________________________________________________

// keySwitchedCipherBytesStruct is the a key switching message structure in bytes
type keySwitchedCipherBytesStruct struct {
	*onet.TreeNode
	KeySwitchedCipherBytesMessage
}

// kscbLengthStruct is the structure containing a lengths message
type kscbLengthStruct struct {
	*onet.TreeNode
	KSCBLengthMessage
}

// Protocol
//______________________________________________________________________________________________________________________

// KeySwitchingProtocol is a struct holding the state of a protocol instance.
type KeySwitchingProtocol struct {
	*onet.TreeNodeInstance

	// Protocol feedback channel
	FeedbackChannel chan libunlynx.CipherVector

	// Protocol communication channels
	PreviousNodeInPathChannel chan keySwitchedCipherBytesStruct
	LengthNodeChannel         chan kscbLengthStruct

	ExecTime time.Duration

	// Protocol state data
	nextNodeInCircuit *onet.TreeNode
	TargetOfSwitch    *libunlynx.CipherVector
	TargetPublicKey   *kyber.Point
	Proofs            bool
}

// NewKeySwitchingProtocol is constructor of Key Switching protocol instances.
func NewKeySwitchingProtocol(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	ksp := &KeySwitchingProtocol{
		TreeNodeInstance: n,
		FeedbackChannel:  make(chan libunlynx.CipherVector),
	}

	if err := ksp.RegisterChannel(&ksp.PreviousNodeInPathChannel); err != nil {
		return nil, errors.New("couldn't register data reference channel: " + err.Error())
	}

	if err := ksp.RegisterChannel(&ksp.LengthNodeChannel); err != nil {
		return nil, errors.New("couldn't register data reference channel: " + err.Error())
	}

	var i int
	var node *onet.TreeNode
	var nodeList = n.Tree().List()
	for i, node = range nodeList {
		if n.TreeNode().Equal(node) {
			ksp.nextNodeInCircuit = nodeList[(i+1)%len(nodeList)]
			break
		}
	}

	return ksp, nil
}

// Start is called at the root to start the execution of the key switching.
func (p *KeySwitchingProtocol) Start() error {

	startRound := libunlynx.StartTimer(p.Name() + "_KeySwitching(START)")

	if p.TargetOfSwitch == nil {
		return errors.New("no ciphertext given as key switching target")
	}

	if p.TargetPublicKey == nil {
		return errors.New("no new public key to be switched on provided")
	}

	p.ExecTime = 0

	log.Lvl1(p.ServerIdentity(), " started a Key Switching Protocol")

	// Initializes the target ciphertext and extract the original ephemeral keys.
	dataLength := len(*p.TargetOfSwitch)
	initialTab := make([]DataAndOriginalEphemeralKeys, dataLength)

	if libunlynx.PARALLELIZE {
		var wg sync.WaitGroup
		for i := 0; i < len(*p.TargetOfSwitch); i += libunlynx.VPARALLELIZE {
			wg.Add(1)
			go func(i int) {
				for j := 0; j < libunlynx.VPARALLELIZE && (j+i < len(*p.TargetOfSwitch)); j++ {
					initialAttribute, originalEphemKey := getAttributesAndEphemKeys((*p.TargetOfSwitch)[i+j])
					initialTab[i+j] = DataAndOriginalEphemeralKeys{ Response: initialAttribute, OriginalEphemeralKey: originalEphemKey }
				}
				defer wg.Done()
			}(i)
		}
		wg.Wait()
	} else {
		for k, v := range *p.TargetOfSwitch {
			initialAttribute, originalEphemKey := getAttributesAndEphemKeys(v)
			initialTab[k] = DataAndOriginalEphemeralKeys{ Response:	initialAttribute, OriginalEphemeralKey:originalEphemKey }
		}
	}
	libunlynx.EndTimer(startRound)
	sending(p, &KeySwitchedCipherMessage{initialTab, *p.TargetPublicKey})

	return nil
}

// getAttributesAndEphemKeys retrieves attributes and ephemeral keys in a CipherVector to be key switched
func getAttributesAndEphemKeys(ct libunlynx.CipherText) (libunlynx.CipherText, kyber.Point) {
	initialAttribute := *libunlynx.NewCipherText()
	initialAttribute.C = ct.C
	originalEphemKey := ct.K
	return initialAttribute, originalEphemKey
}

// Dispatch is called on each node. It waits for incoming messages and handles them.
func (p *KeySwitchingProtocol) Dispatch() error {
	length := <-p.LengthNodeChannel
	keySwitchingTargetBytes := (<-p.PreviousNodeInPathChannel).KeySwitchedCipherBytesMessage.Data
	keySwitchingTarget := &KeySwitchedCipherMessage{}
	(*keySwitchingTarget).FromBytes(keySwitchingTargetBytes, length.LenB)
	round := libunlynx.StartTimer(p.Name() + "_KeySwitching(DISPATCH)")
	startT := time.Now()


	/*
	wg := libunlynx.StartParallelize(len(keySwitchingTarget.DataKey))

	for i, v := range keySwitchingTarget.DataKey {
		origGrpEphemKeys := v.OriginalEphemeralKeys.GroupOriginalKeys
		origAttrEphemKeys := v.OriginalEphemeralKeys.AttrOriginalKeys
		if libunlynx.PARALLELIZE {
			go func(i int, v DataAndOriginalEphemeralKeys, origGrpEphemKeys, origAttrEphemKeys []kyber.Point) {
				FilteredResponseKeySwitching(&keySwitchingTarget.DataKey[i].Response, v.Response, origGrpEphemKeys,
					origAttrEphemKeys, keySwitchingTarget.NewKey, p.Private(), p.Proofs)
				defer wg.Done()
			}(i, v, origGrpEphemKeys, origAttrEphemKeys)
		} else {
			FilteredResponseKeySwitching(&keySwitchingTarget.DataKey[i].Response, v.Response, origGrpEphemKeys,
				origAttrEphemKeys, keySwitchingTarget.NewKey, p.Private(), p.Proofs)
		}
	}
	*/
	FilteredResponseKeySwitching(keySwitchingTarget, p.Private(), p.Proofs)

	libunlynx.EndTimer(round)

	// If the tree node is the root then protocol returns.
	if p.IsRoot() {
		log.Lvl1(p.ServerIdentity(), " completed key switching.")
		result := make(libunlynx.CipherVector, len(keySwitchingTarget.DataKey))
		for i, v := range keySwitchingTarget.DataKey {
			result[i] = v.Response
		}
		p.ExecTime += time.Since(startT)
		p.FeedbackChannel <- result
	} else {
		log.Lvl1(p.ServerIdentity(), " carried on key switching on ", len(keySwitchingTarget.DataKey), " .")
		sending(p, keySwitchingTarget)
	}

	return nil
}

// sendToNext sends the message msg to the next node in the circuit based on the next TreeNode in Tree.List() If not visited yet.
// If the message already visited the next node, doesn't send and returns false. Otherwise, return true.
func (p *KeySwitchingProtocol) sendToNext(msg interface{}) {
	err := p.SendTo(p.nextNodeInCircuit, msg)
	if err != nil {
		log.Lvl1(p.Name(), " has an error sending a message: ", err)
	}
}

// sending sends KeySwitchedCipherBytes messages
func sending(p *KeySwitchingProtocol, kscm *KeySwitchedCipherMessage) {
	data, lenB := kscm.ToBytes()
	p.sendToNext(&KSCBLengthMessage{LenB: lenB})
	p.sendToNext(&KeySwitchedCipherBytesMessage{data})
}

//FilteredResponseKeySwitching applies key switching on a ciphervector
func FilteredResponseKeySwitching(keySwitchingTarget *KeySwitchedCipherMessage, secretContrib kyber.Scalar, proofsB bool) {

    length := len(keySwitchingTarget.DataKey)
	r := make([]kyber.Scalar, length)
	originalEphemeralKeys := make([]kyber.Point, length)
	newCv := make(libunlynx.CipherVector, length)
	oldCv := make(libunlynx.CipherVector, length)
	if libunlynx.PARALLELIZE {
		var wg sync.WaitGroup
		for i := 0; i < len(keySwitchingTarget.DataKey); i += libunlynx.VPARALLELIZE {
			wg.Add(1)
			go func(i int){
				for j := 0; j < libunlynx.VPARALLELIZE && (i+j) < len(keySwitchingTarget.DataKey); j++ {
					tmp := libunlynx.NewCipherText()
					oldCv[i+j] = keySwitchingTarget.DataKey[i+j].Response
					r[i+j] = tmp.KeySwitching(keySwitchingTarget.DataKey[i+j].Response, keySwitchingTarget.DataKey[i+j].OriginalEphemeralKey,
						keySwitchingTarget.NewKey, secretContrib)
					keySwitchingTarget.DataKey[i+j].Response = *tmp
					newCv[i+j] = *tmp
					originalEphemeralKeys[i+j] = keySwitchingTarget.DataKey[i+j].OriginalEphemeralKey
				}
				defer wg.Done()
			}(i)
		}
		wg.Wait()
	} else {
		for i, v := range keySwitchingTarget.DataKey {
			tmp := libunlynx.NewCipherText()
			oldCv[i] = v.Response
			r[i] = tmp.KeySwitching(keySwitchingTarget.DataKey[i].Response, v.OriginalEphemeralKey, keySwitchingTarget.NewKey , secretContrib)
			keySwitchingTarget.DataKey[i].Response = *tmp
			originalEphemeralKeys[i] = v.OriginalEphemeralKey
			newCv[i] = *tmp
		}
	}

	if proofsB {
		proof := libunlynxproofs.VectorSwitchKeyProofCreation(oldCv, newCv, r, secretContrib, originalEphemeralKeys, keySwitchingTarget.NewKey)
		pubKey := libunlynx.SuiTe.Point().Mul(secretContrib, libunlynx.SuiTe.Point().Base())
		pub := libunlynxproofs.PublishedSwitchKeyProof{Skp: proof, VectBefore: oldCv, VectAfter: newCv, K: pubKey, Q: keySwitchingTarget.NewKey}
		_ = pub
	}
}

/*
//FilteredResponseKeySwitching applies key switching on a filtered response
func FilteredResponseKeySwitching(cv *libunlynx.FilteredResponse, v libunlynx.FilteredResponse, origGrpEphemKeys, origAttrEphemKeys []kyber.Point, newKey kyber.Point, secretContrib kyber.Scalar, proofsB bool) {
	tmp := libunlynx.NewCipherVector(len(v.AggregatingAttributes))
	r1 := tmp.KeySwitching(v.AggregatingAttributes, origAttrEphemKeys, newKey, secretContrib)
	cv.AggregatingAttributes = *tmp

	tmp1 := libunlynx.NewCipherVector(len(v.GroupByEnc))
	r2 := tmp1.KeySwitching(v.GroupByEnc, origGrpEphemKeys, newKey, secretContrib)
	cv.GroupByEnc = *tmp1



	if proofsB {
		proofAggr := proofs.VectorSwitchKeyProofCreation(v.AggregatingAttributes, cv.AggregatingAttributes, r1, secretContrib, origAttrEphemKeys, newKey)
		proofGrp := proofs.VectorSwitchKeyProofCreation(v.GroupByEnc, cv.GroupByEnc, r2, secretContrib, origGrpEphemKeys, newKey)
		//create published value
		pubKey := libunlynx.SuiTe.Point().Mul(secretContrib, libunlynx.SuiTe.Point().Base())
		pub1 := proofs.PublishedSwitchKeyProof{Skp: proofAggr, VectBefore: v.AggregatingAttributes, VectAfter: cv.AggregatingAttributes, K: pubKey, Q: newKey}
		pub2 := proofs.PublishedSwitchKeyProof{Skp: proofGrp, VectBefore: v.GroupByEnc, VectAfter: cv.GroupByEnc, K: pubKey, Q: newKey}
		//publication
		_ = pub1
		_ = pub2
	}
}
*/

// Conversion
//______________________________________________________________________________________________________________________

// ToBytes converts a KeySwitchedCipherMessage to a byte array
func (kscm *KeySwitchedCipherMessage) ToBytes() ([]byte, int) {
	bb := make([][]byte, len(kscm.DataKey))

	if libunlynx.PARALLELIZE {
		var wg sync.WaitGroup
		var mutexDK sync.Mutex
		for i := 0; i < len(kscm.DataKey); i += libunlynx.VPARALLELIZE {
			wg.Add(1)
			go func(i int) {
				for j := 0; j < libunlynx.VPARALLELIZE && (i+j) < len(kscm.DataKey); j++ {
					mutexDK.Lock()
					data := (*kscm).DataKey[i+j]
					mutexDK.Unlock()

					aux := data.ToBytes()

					mutexDK.Lock()
					bb[i+j] = aux
					mutexDK.Unlock()
				}
				defer wg.Done()
			}(i)
		}
		wg.Wait()
	} else {
		for i, v := range (*kscm).DataKey {
			bb[i] = v.ToBytes()
		}
	}
	nkb := libunlynx.AbstractPointsToBytes([]kyber.Point{(*kscm).NewKey})

	b := make([]byte, 0)
	for i := range bb {
		b = append(b, bb[i]...)
	}
	return append(b, nkb...), len(b)
}

// FromBytes converts a byte array to a KeySwitchedCipherMessage. Note that you need to create the (empty) object beforehand.
func (kscm *KeySwitchedCipherMessage) FromBytes(data []byte, lenb int) {
	elementSize := libunlynx.ByteArraySize + (libunlynx.ByteArraySize / 2)
	nkb := data[lenb:]
	(*kscm).NewKey = libunlynx.BytesToAbstractPoints(nkb)[0]
	(*kscm).DataKey = make([]DataAndOriginalEphemeralKeys, lenb / elementSize)

	if libunlynx.PARALLELIZE {
		var wg sync.WaitGroup
	    for i := 0; i < lenb; i += elementSize * libunlynx.VPARALLELIZE {
			wg.Add(1)
			go func(i int) {
				for j := 0; j < elementSize * libunlynx.VPARALLELIZE && (i+j < lenb); j += elementSize {
					tmp := data[(i+j):(i+j+elementSize)]
					(*kscm).DataKey[(i+j) / elementSize] = DataAndOriginalEphemeralKeys{}
					(*kscm).DataKey[(i+j) / elementSize].FromBytes(tmp)
				}
				defer wg.Done()
			}(i)
		}
		wg.Wait()
	} else {
		for i := 0; i < lenb; i += libunlynx.ByteArraySize {
			tmp := data[i:i+libunlynx.ByteArraySize]
			(*kscm).DataKey[i / libunlynx.ByteArraySize] = DataAndOriginalEphemeralKeys{}
			(*kscm).DataKey[i / libunlynx.ByteArraySize].FromBytes(tmp)
		}
	}
}

// ToBytes converts a DataAndOriginalEphemeralKeys to a byte array
func (daoek *DataAndOriginalEphemeralKeys) ToBytes() []byte  {
	b := make([]byte, 0)
	bResponse := (*daoek).Response.ToBytes()
	bEphKey, errBin := daoek.OriginalEphemeralKey.MarshalBinary()
	if errBin != nil {
		log.Fatal(errBin)
	}
	b = append(bResponse, bEphKey...)

	return b
}

// FromBytes converts a byte array to a DataAndOriginalEphemeralKeys. Note that you need to create the (empty) object beforehand.
func (daoek *DataAndOriginalEphemeralKeys) FromBytes(data []byte) {
	(*daoek).Response.FromBytes(data[:libunlynx.ByteArraySize])
	(*daoek).OriginalEphemeralKey = libunlynx.SuiTe.Point()
	(*daoek).OriginalEphemeralKey.UnmarshalBinary(data[libunlynx.ByteArraySize:])
}

/*
// ToBytes converts a OriginalEphemeralKeys to a byte array
func (oek *OriginalEphemeralKeys) ToBytes() ([]byte, int, int) {
	groupBytes := libunlynx.AbstractPointsToBytes(oek.GroupOriginalKeys)
	aggrBytes := libunlynx.AbstractPointsToBytes(oek.AttrOriginalKeys)
	return append(groupBytes, aggrBytes...), len(groupBytes), len(aggrBytes)
}

// FromBytes converts a byte array to a OriginalEphemeralKeys. Note that you need to create the (empty) object beforehand.
func (oek *OriginalEphemeralKeys) FromBytes(data []byte, groupLength int) {
	group := libunlynx.BytesToAbstractPoints(data[:groupLength])
	aggr := libunlynx.BytesToAbstractPoints(data[groupLength:])

	(*oek).GroupOriginalKeys = group
	(*oek).AttrOriginalKeys = aggr
}
*/
