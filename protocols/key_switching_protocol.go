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
	"github.com/lca1/unlynx/lib"
	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
	"github.com/dedis/onet/network"
	"sync"
	"time"
	"github.com/dedis/kyber"
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

// DataAndOriginalEphemeralKeys contains data being switched and the original ephemeral keys needed at each step
type DataAndOriginalEphemeralKeys struct {
	Response              libunlynx.FilteredResponse
	OriginalEphemeralKeys OriginalEphemeralKeys
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
	L1 int
	L2 int
	L4 int
	L5 int
	L6 int
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
	FeedbackChannel chan []libunlynx.FilteredResponse

	// Protocol communication channels
	PreviousNodeInPathChannel chan keySwitchedCipherBytesStruct
	LengthNodeChannel         chan kscbLengthStruct

	ExecTime time.Duration

	// Protocol state data
	nextNodeInCircuit *onet.TreeNode
	TargetOfSwitch    *[]libunlynx.FilteredResponse
	TargetPublicKey   *kyber.Point
	Proofs            bool
}

// NewKeySwitchingProtocol is constructor of Key Switching protocol instances.
func NewKeySwitchingProtocol(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	ksp := &KeySwitchingProtocol{
		TreeNodeInstance: n,
		FeedbackChannel:  make(chan []libunlynx.FilteredResponse),
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

	wg := libunlynx.StartParallelize(0)

	if libunlynx.PARALLELIZE {
		for i := 0; i < len(*p.TargetOfSwitch); i = i + libunlynx.VPARALLELIZE {
			wg.Add(1)
			go func(i int) {
				for j := 0; j < libunlynx.VPARALLELIZE && (j+i < len(*p.TargetOfSwitch)); j++ {
					initialAttrAttributes, originalAttrEphemKeys := getAttributesAndEphemKeys((*p.TargetOfSwitch)[i+j].AggregatingAttributes)
					initialGrpAttributes, originalGrpEphemKeys := getAttributesAndEphemKeys((*p.TargetOfSwitch)[i+j].GroupByEnc)

					initialTab[i+j] = DataAndOriginalEphemeralKeys{Response: libunlynx.FilteredResponse{GroupByEnc: initialGrpAttributes, AggregatingAttributes: initialAttrAttributes},
						OriginalEphemeralKeys: OriginalEphemeralKeys{GroupOriginalKeys: originalGrpEphemKeys, AttrOriginalKeys: originalAttrEphemKeys}}
				}
				defer wg.Done()
			}(i)

		}
		libunlynx.EndParallelize(wg)
	} else {
		for k, v := range *p.TargetOfSwitch {
			initialAttrAttributes, originalAttrEphemKeys := getAttributesAndEphemKeys(v.AggregatingAttributes)
			initialGrpAttributes, originalGrpEphemKeys := getAttributesAndEphemKeys(v.GroupByEnc)

			initialTab[k] = DataAndOriginalEphemeralKeys{Response: libunlynx.FilteredResponse{GroupByEnc: initialGrpAttributes, AggregatingAttributes: initialAttrAttributes},
				OriginalEphemeralKeys: OriginalEphemeralKeys{GroupOriginalKeys: originalGrpEphemKeys, AttrOriginalKeys: originalAttrEphemKeys}}
		}
	}
	libunlynx.EndTimer(startRound)
	sending(p, &KeySwitchedCipherMessage{initialTab, *p.TargetPublicKey})

	return nil
}

// getAttributesAndEphemKeys retrieves attributes and ephemeral keys in a CipherVector to be key switched
func getAttributesAndEphemKeys(cv libunlynx.CipherVector) (libunlynx.CipherVector, []kyber.Point) {
	length := len(cv)
	initialAttributes := *libunlynx.NewCipherVector(length)
	originalEphemKeys := make([]kyber.Point, length)
	for i, c := range cv {
		initialAttributes[i].C = c.C
		originalEphemKeys[i] = c.K
	}
	return initialAttributes, originalEphemKeys
}

// Dispatch is called on each node. It waits for incoming messages and handles them.
func (p *KeySwitchingProtocol) Dispatch() error {

	length := <-p.LengthNodeChannel
	keySwitchingTargetBytes := (<-p.PreviousNodeInPathChannel).KeySwitchedCipherBytesMessage.Data
	keySwitchingTarget := &KeySwitchedCipherMessage{}
	(*keySwitchingTarget).FromBytes(keySwitchingTargetBytes, length.L1, length.L2, length.L4, length.L5, length.L6)
	round := libunlynx.StartTimer(p.Name() + "_KeySwitching(DISPATCH)")
	startT := time.Now()

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

	libunlynx.EndParallelize(wg)
	libunlynx.EndTimer(round)

	// If the tree node is the root then protocol returns.
	if p.IsRoot() {
		log.Lvl1(p.ServerIdentity(), " completed key switching.")
		result := make([]libunlynx.FilteredResponse, len(keySwitchingTarget.DataKey))
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
	data, l1, l2, l4, l5, l6 := kscm.ToBytes()
	p.sendToNext(&KSCBLengthMessage{l1, l2, l4, l5, l6})
	p.sendToNext(&KeySwitchedCipherBytesMessage{data})
}

//FilteredResponseKeySwitching applies key switching on a filtered response
func FilteredResponseKeySwitching(cv *libunlynx.FilteredResponse, v libunlynx.FilteredResponse, origGrpEphemKeys, origAttrEphemKeys []kyber.Point, newKey kyber.Point, secretContrib kyber.Scalar, proofs bool) {
	tmp := libunlynx.NewCipherVector(len(v.AggregatingAttributes))
	r1 := tmp.KeySwitching(v.AggregatingAttributes, origAttrEphemKeys, newKey, secretContrib)
	cv.AggregatingAttributes = *tmp

	tmp1 := libunlynx.NewCipherVector(len(v.GroupByEnc))
	r2 := tmp1.KeySwitching(v.GroupByEnc, origGrpEphemKeys, newKey, secretContrib)
	cv.GroupByEnc = *tmp1

	if proofs {
		proofAggr := libunlynx.VectorSwitchKeyProofCreation(v.AggregatingAttributes, cv.AggregatingAttributes, r1, secretContrib, origAttrEphemKeys, newKey)
		proofGrp := libunlynx.VectorSwitchKeyProofCreation(v.GroupByEnc, cv.GroupByEnc, r2, secretContrib, origGrpEphemKeys, newKey)
		//create published value
		pubKey := libunlynx.SuiTe.Point().Mul(secretContrib, libunlynx.SuiTe.Point().Base())
		pub1 := libunlynx.PublishedSwitchKeyProof{Skp: proofAggr, VectBefore: v.AggregatingAttributes, VectAfter: cv.AggregatingAttributes, K: pubKey, Q: newKey}
		pub2 := libunlynx.PublishedSwitchKeyProof{Skp: proofGrp, VectBefore: v.GroupByEnc, VectAfter: cv.GroupByEnc, K: pubKey, Q: newKey}
		//publication
		_ = pub1
		_ = pub2
	}
}

// Conversion
//______________________________________________________________________________________________________________________

// ToBytes converts a KeySwitchedCipherMessage to a byte array
func (kscm *KeySwitchedCipherMessage) ToBytes() ([]byte, int, int, int, int, int) {
	bb := make([][]byte, len(kscm.DataKey))
	var l1, l2, l4, l5 int

	wg := libunlynx.StartParallelize(len(kscm.DataKey))
	var mutexDK sync.Mutex
	for i := range (*kscm).DataKey {
		if libunlynx.PARALLELIZE {
			go func(i int) {
				defer wg.Done()

				mutexDK.Lock()
				data := (*kscm).DataKey[i]
				mutexDK.Unlock()

				aux, l1Aux, l2Aux, l4Aux, l5Aux := data.ToBytes()

				mutexDK.Lock()
				bb[i] = aux
				l1 = l1Aux
				l2 = l2Aux
				l4 = l4Aux
				l5 = l5Aux
				mutexDK.Unlock()

			}(i)
		} else {
			bb[i], l1, l2, l4, l5 = (*kscm).DataKey[i].ToBytes()
		}

	}
	libunlynx.EndParallelize(wg)
	nkb := libunlynx.AbstractPointsToBytes([]kyber.Point{(*kscm).NewKey})

	b := make([]byte, 0)
	for i := range bb {
		b = append(b, bb[i]...)
	}
	l6 := len(b)
	return append(b, nkb...), l1, l2, l4, l5, l6
}

// FromBytes converts a byte array to a KeySwitchedCipherMessage. Note that you need to create the (empty) object beforehand.
func (kscm *KeySwitchedCipherMessage) FromBytes(data []byte, l1, l2, l4, l5, l6 int) {
	bb := make([][]byte, 0)
	tmp := l1*64 + l2*64 + l4 + l5
	for i := 0; i < l6-32; i += tmp {
		bb = append(bb, data[i:i+tmp])
	}

	wg := libunlynx.StartParallelize(len(bb))
	(*kscm).DataKey = make([]DataAndOriginalEphemeralKeys, len(bb))
	for i := range bb {
		if libunlynx.PARALLELIZE {
			go func(i int) {
				defer wg.Done()
				daoek := DataAndOriginalEphemeralKeys{}
				daoek.FromBytes(bb[i], l1, l2, l4)
				(*kscm).DataKey[i] = daoek
			}(i)
		} else {
			daoek := DataAndOriginalEphemeralKeys{}
			daoek.FromBytes(bb[i], l1, l2, l4)
			(*kscm).DataKey[i] = daoek
		}
	}
	libunlynx.EndParallelize(wg)
	point := (data)[l6:]
	temp := libunlynx.BytesToAbstractPoints(point)
	(*kscm).NewKey = temp[0]
}

// ToBytes converts a DataAndOriginalEphemeralKeys to a byte array
func (daoek *DataAndOriginalEphemeralKeys) ToBytes() ([]byte, int, int, int, int) {
	b := make([]byte, 0)
	b1, l1, l2 := (*daoek).Response.ToBytes()
	b2, l4, l5 := daoek.OriginalEphemeralKeys.ToBytes()
	b = append(b1, b2...)

	return b, l1, l2, l4, l5
}

// FromBytes converts a byte array to a DataAndOriginalEphemeralKeys. Note that you need to create the (empty) object beforehand.
func (daoek *DataAndOriginalEphemeralKeys) FromBytes(data []byte, l1, l2, l4 int) {
	resp := libunlynx.FilteredResponse{}
	resp.FromBytes(data[:l1*64+l2*64], l2, l1)
	(*daoek).Response = resp

	oek := OriginalEphemeralKeys{}
	oek.FromBytes(data[l1*64+l2*64:], l4)
	(*daoek).OriginalEphemeralKeys = oek
}

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
