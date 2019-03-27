// Package protocolsunlynx implements the key switching protocol.
// It permits to switch a ciphertext encrypted under a specific key to another ciphertext encrypted under another key.
// To do this each cothority server (node) removes its secret contribution and homomorphically adds the ciphertexts with
// a new secret contribution containing the new key.
// This protocol operates in a circuit between the servers: the data is sent sequentially through this circuit and
// each server applies its transformation.
package protocolsunlynx

import (
	"errors"

	"github.com/dedis/kyber"
	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
	"github.com/dedis/onet/network"
	"github.com/lca1/unlynx/lib"
	"github.com/lca1/unlynx/lib/key_switch"
)

// KeySwitchingProtocolName is the registered name for the collective aggregation protocol.
const KeySwitchingProtocolName = "KeySwitching"

func init() {
	network.RegisterMessage(DownMessage{})
	network.RegisterMessage(DownMessageBytes{})
	network.RegisterMessage(UpMessage{})
	network.RegisterMessage(UpBytesMessage{})
	network.RegisterMessage(LengthMessage{})
	if _, err := onet.GlobalProtocolRegister(KeySwitchingProtocolName, NewKeySwitchingProtocol); err != nil {
		log.Fatal("Failed to register the <KeySwitching> protocol:", err)
	}
}

// Messages
//______________________________________________________________________________________________________________________

// DownMessage message sent down the tree containing all the rB (left part of ciphertexts)
type DownMessage struct {
	NewKey kyber.Point
	Rbs    []kyber.Point
}

// DownMessageBytes message sent down the tree containing all the rB (left part of ciphertexts) in bytes
type DownMessageBytes struct {
	Data []byte
}

// UpMessage contains the ciphertext used by the servers to create their key switching contribution.
type UpMessage struct {
	ChildData []libunlynx.CipherText
}

// UpBytesMessage is UpMessage in bytes.
type UpBytesMessage struct {
	Data []byte
}

// LengthMessage is a message containing the length of a message in bytes
type LengthMessage struct {
	Length []byte
}

// Structs
//______________________________________________________________________________________________________________________

// DownBytesStruct struct used to send DownMessage(Bytes)
type DownBytesStruct struct {
	*onet.TreeNode
	DownMessageBytes
}

// UpBytesStruct struct used to send Up(Bytes)Message
type UpBytesStruct struct {
	*onet.TreeNode
	UpBytesMessage
}

// LengthStruct struct used to send LengthMessage
type LengthStruct struct {
	*onet.TreeNode
	LengthMessage
}

// proofKeySwitchFunction defines a function that does 'stuff' with the key switch proofs
type proofKeySwitchFunction func(kyber.Point, kyber.Point, kyber.Scalar, []kyber.Point, []kyber.Point, []kyber.Scalar) *libunlynxkeyswitch.PublishedKSListProof

// Protocol
//______________________________________________________________________________________________________________________

// KeySwitchingProtocol performs an aggregation of the data held by every node in the cothority.
type KeySwitchingProtocol struct {
	*onet.TreeNodeInstance

	// Protocol feedback channel
	FeedbackChannel chan libunlynx.CipherVector

	// Protocol communication channels
	DownChannel      chan DownBytesStruct
	LengthChannel    chan []LengthStruct
	ChildDataChannel chan []UpBytesStruct

	// Protocol root data
	NodeContribution *libunlynx.CipherVector

	// Protocol state data
	TargetOfSwitch  *libunlynx.CipherVector
	TargetPublicKey *kyber.Point

	// Proofs
	Proofs    bool
	ProofFunc proofKeySwitchFunction           // proof function for when we want to do something different with the proofs (e.g. insert in the blockchain)
	MapPIs    map[string]onet.ProtocolInstance // protocol instances to be able to call protocols inside protocols (e.g. proof_collection_protocol)
}

// NewKeySwitchingProtocol initializes the protocol instance.
func NewKeySwitchingProtocol(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	pap := &KeySwitchingProtocol{
		TreeNodeInstance: n,
		FeedbackChannel:  make(chan libunlynx.CipherVector),
	}

	err := pap.RegisterChannel(&pap.DownChannel)
	if err != nil {
		return nil, errors.New("couldn't register down channel: " + err.Error())
	}

	err = pap.RegisterChannel(&pap.ChildDataChannel)
	if err != nil {
		return nil, errors.New("couldn't register child-data channel: " + err.Error())
	}

	if err := pap.RegisterChannel(&pap.LengthChannel); err != nil {
		return nil, errors.New("couldn't register length channel: " + err.Error())
	}

	return pap, nil
}

// Start is called at the root to begin the execution of the protocol.
func (p *KeySwitchingProtocol) Start() error {

	//keySwitchingStart := libunlynx.StartTimer(p.Name() + "_KeySwitching(START)")

	if p.TargetOfSwitch == nil {
		return errors.New("no ciphertext given as key switching target")
	}

	if p.TargetPublicKey == nil {
		return errors.New("no new public key to be switched on provided")
	}

	log.Lvl2("[KEY SWITCHING PROTOCOL] <Drynx> Server", p.ServerIdentity(), " started a Key Switching Protocol")

	// Initializes the target ciphertext and extract the original ephemeral keys.
	dataLength := len(*p.TargetOfSwitch)
	initialTab := make([]kyber.Point, dataLength+1)

	// put the target public key in first position
	initialTab[0] = *p.TargetPublicKey
	for i, v := range *p.TargetOfSwitch {
		initialTab[i+1] = v.K
	}

	// root does its key switching
	switchedCiphers, ks2s, rBNegs, vis := libunlynxkeyswitch.KeySwitchSequence(*p.TargetPublicKey, initialTab[1:], p.Private())
	if p.Proofs {
		p.ProofFunc(p.Public(), *p.TargetPublicKey, p.Private(), ks2s, rBNegs, vis)
	}
	p.NodeContribution = &switchedCiphers

	if p.SendToChildren(&DownMessageBytes{Data: libunlynx.AbstractPointsToBytes(initialTab)}) != nil {
		log.Fatal("Root " + p.ServerIdentity().String() + " failed to broadcast DownMessageBytes")
	}

	//libunlynx.EndTimer(keySwitchingStart)

	return nil
}

// Dispatch is called at each node and handle incoming messages.
func (p *KeySwitchingProtocol) Dispatch() error {
	defer p.Done()

	// 1. Key switching announcement phase
	if !p.IsRoot() {
		targetPublicKey, rbs := p.announcementKSPhase()

		switchedCiphers, ks2s, rBNegs, vis := libunlynxkeyswitch.KeySwitchSequence(targetPublicKey, rbs, p.Private())
		if p.Proofs {
			p.ProofFunc(p.Public(), targetPublicKey, p.Private(), ks2s, rBNegs, vis)
		}
		p.NodeContribution = &switchedCiphers
	}

	// 2. Ascending key switching phase
	p.ascendingKSPhase()

	// 3. Response reporting
	if p.IsRoot() {
		ksCiphers := *libunlynx.NewCipherVector(len(*p.TargetOfSwitch))

		wg := libunlynx.StartParallelize(len(*p.TargetOfSwitch))
		for i, v := range *p.TargetOfSwitch {
			go func(i int, v libunlynx.CipherText) {
				defer wg.Done()
				ksCiphers[i].K = (*p.NodeContribution)[i].K
				ksCiphers[i].C = libunlynx.SuiTe.Point().Add((*p.NodeContribution)[i].C, v.C)
			}(i, v)
		}
		libunlynx.EndParallelize(wg)
		p.FeedbackChannel <- ksCiphers
	}
	return nil
}

// Announce forwarding down the tree.
func (p *KeySwitchingProtocol) announcementKSPhase() (kyber.Point, []kyber.Point) {
	dataReferenceMessage := <-p.DownChannel
	if !p.IsLeaf() {
		if p.SendToChildren(&dataReferenceMessage.DownMessageBytes) != nil {
			log.Fatal("Node " + p.ServerIdentity().String() + " failed to broadcast DownMessageBytes")
		}
	}
	message := libunlynx.FromBytesToAbstractPoints(dataReferenceMessage.Data)

	return message[0], message[1:]
}

// Results pushing up the tree containing key switching results.
func (p *KeySwitchingProtocol) ascendingKSPhase() *libunlynx.CipherVector {

	//keySwitchingAscendingAggregation := libunlynx.StartTimer(p.Name() + "_KeySwitching(ascendingAggregation)")

	if !p.IsLeaf() {
		length := make([]LengthStruct, 0)
		for _, v := range <-p.LengthChannel {
			length = append(length, v)
		}

		datas := make([]UpBytesStruct, 0)
		for _, v := range <-p.ChildDataChannel {
			datas = append(datas, v)
		}
		for i := range length { // len of length is number of children
			cv := libunlynx.CipherVector{}
			cv.FromBytes(datas[i].Data, libunlynx.UnsafeCastBytesToInts(length[i].Length)[0])
			sumCv := libunlynx.NewCipherVector(len(cv))
			sumCv.Add(*p.NodeContribution, cv)
			p.NodeContribution = sumCv

		}
	}

	//libunlynx.EndTimer(keySwitchingAscendingAggregation)

	if !p.IsRoot() {
		if err := p.SendToParent(&LengthMessage{Length: libunlynx.UnsafeCastIntsToBytes([]int{len(*p.NodeContribution)})}); err != nil {
			log.Fatal("Node "+p.ServerIdentity().String()+" failed to broadcast LengthMessage (", err, ")")
		}
		message, _ := (*p.NodeContribution).ToBytes()
		if p.SendToParent(&UpBytesMessage{Data: message}) != nil {
			log.Fatal("Node " + p.ServerIdentity().String() + " failed to broadcast UpBytesMessage")
		}
	}

	return p.NodeContribution
}
