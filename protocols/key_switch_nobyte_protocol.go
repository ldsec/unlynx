package protocols

import (
	"errors"

	"github.com/lca1/unlynx/lib"
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/dedis/onet.v1/network"

	"time"
)

// KeySwitchingProtocolName is the registered name for the key switching protocol.
const KeySwitchingNoByteProtocolName = "KeySwitchingNoByte"

func init() {
	network.RegisterMessage(KeySwitchedCipherMessage{})
	//network.RegisterMessage(KeySwitchedCipherBytesMessage{})
	//network.RegisterMessage(KSCBLengthMessage{})
	onet.GlobalProtocolRegister(KeySwitchingNoByteProtocolName, NewKeySwitchingNoByteProtocol)
}

// Messages
//______________________________________________________________________________________________________________________

// Structs
//______________________________________________________________________________________________________________________

// keySwitchedCipherBytesStruct is the a key switching message structure in bytes
type keySwitchedCipherNoBytesStruct struct {
	*onet.TreeNode
	KeySwitchedCipherMessage
}

// Protocol
//______________________________________________________________________________________________________________________

// KeySwitchingProtocol is a struct holding the state of a protocol instance.
type KeySwitchingNoByteProtocol struct {
	*onet.TreeNodeInstance

	// Protocol feedback channel
	FeedbackChannel chan []lib.FilteredResponse

	// Protocol communication channels
	PreviousNodeInPathChannel chan keySwitchedCipherNoBytesStruct

	ExecTime time.Duration

	// Protocol state data
	nextNodeInCircuit *onet.TreeNode
	TargetOfSwitch    *[]lib.FilteredResponse
	TargetPublicKey   *abstract.Point
	Proofs            bool
}

// NewKeySwitchingProtocol is constructor of Key Switching protocol instances.
func NewKeySwitchingNoByteProtocol(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	ksp := &KeySwitchingNoByteProtocol{
		TreeNodeInstance: n,
		FeedbackChannel:  make(chan []lib.FilteredResponse),
	}

	if err := ksp.RegisterChannel(&ksp.PreviousNodeInPathChannel); err != nil {
		return nil, errors.New("couldn't register data reference channel: " + err.Error())
	}

	/*	if err := ksp.RegisterChannel(&ksp.LengthNodeChannel); err != nil {
		return nil, errors.New("couldn't register data reference channel: " + err.Error())
	}*/

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
func (p *KeySwitchingNoByteProtocol) Start() error {

	startRound := lib.StartTimer(p.Name() + "_KeySwitching(START)")
	if p.TargetOfSwitch == nil {
		return errors.New("No ciphertext given as key switching target")
	}

	if p.TargetPublicKey == nil {
		return errors.New("No new public key to be switched on provided")
	}

	p.ExecTime = 0

	log.Lvl1(p.ServerIdentity(), " started a Key Switching Protocol (No bytes)")

	// Initializes the target ciphertext and extract the original ephemeral keys.
	dataLength := len(*p.TargetOfSwitch)
	initialTab := make([]DataAndOriginalEphemeralKeys, dataLength)

	wg := lib.StartParallelize(0)

	if lib.PARALLELIZE {
		for i := 0; i < len(*p.TargetOfSwitch); i = i + lib.VPARALLELIZE {
			wg.Add(1)
			go func(i int) {
				for j := 0; j < lib.VPARALLELIZE && (j+i < len(*p.TargetOfSwitch)); j++ {
					initialAttrAttributes, originalAttrEphemKeys := getAttributesAndEphemKeys((*p.TargetOfSwitch)[i+j].AggregatingAttributes)
					initialGrpAttributes, originalGrpEphemKeys := getAttributesAndEphemKeys((*p.TargetOfSwitch)[i+j].GroupByEnc)

					initialTab[i+j] = DataAndOriginalEphemeralKeys{Response: lib.FilteredResponse{GroupByEnc: initialGrpAttributes, AggregatingAttributes: initialAttrAttributes},
						OriginalEphemeralKeys: OriginalEphemeralKeys{GroupOriginalKeys: originalGrpEphemKeys, AttrOriginalKeys: originalAttrEphemKeys}}
				}
				defer wg.Done()
			}(i)

		}
		lib.EndParallelize(wg)
	} else {
		for k, v := range *p.TargetOfSwitch {
			initialAttrAttributes, originalAttrEphemKeys := getAttributesAndEphemKeys(v.AggregatingAttributes)
			initialGrpAttributes, originalGrpEphemKeys := getAttributesAndEphemKeys(v.GroupByEnc)

			initialTab[k] = DataAndOriginalEphemeralKeys{Response: lib.FilteredResponse{GroupByEnc: initialGrpAttributes, AggregatingAttributes: initialAttrAttributes},
				OriginalEphemeralKeys: OriginalEphemeralKeys{GroupOriginalKeys: originalGrpEphemKeys, AttrOriginalKeys: originalAttrEphemKeys}}
		}
	}
	lib.EndTimer(startRound)
	sendingNoBytes(p, &KeySwitchedCipherMessage{initialTab, *p.TargetPublicKey})
	return nil
}

// Dispatch is called on each node. It waits for incoming messages and handles them.
func (p *KeySwitchingNoByteProtocol) Dispatch() error {
	//start := time.Now()
	//length := <-p.LengthNodeChannel
	//keySwitchingTargetBytes := (<-p.PreviousNodeInPathChannel).KeySwitchedCipherBytesMessage.Data
	keySwitchingTarget := (<-p.PreviousNodeInPathChannel)
	//(*keySwitchingTarget).FromBytes(keySwitchingTargetBytes, length.L1, length.L2, length.L4, length.L5, length.L6)
	round := lib.StartTimer(p.Name() + "_KeySwitching(DISPATCH)")
	startT := time.Now()

	wg := lib.StartParallelize(len(keySwitchingTarget.DataKey))

	for i, v := range keySwitchingTarget.DataKey {
		origGrpEphemKeys := v.OriginalEphemeralKeys.GroupOriginalKeys
		origAttrEphemKeys := v.OriginalEphemeralKeys.AttrOriginalKeys
		if lib.PARALLELIZE {
			go func(i int, v DataAndOriginalEphemeralKeys, origGrpEphemKeys, origAttrEphemKeys []abstract.Point) {
				FilteredResponseKeySwitching(&keySwitchingTarget.DataKey[i].Response, v.Response, origGrpEphemKeys,
					origAttrEphemKeys, keySwitchingTarget.NewKey, p.Private(), p.Proofs)
				defer wg.Done()
			}(i, v, origGrpEphemKeys, origAttrEphemKeys)
		} else {
			FilteredResponseKeySwitching(&keySwitchingTarget.DataKey[i].Response, v.Response, origGrpEphemKeys,
				origAttrEphemKeys, keySwitchingTarget.NewKey, p.Private(), p.Proofs)
		}
	}

	lib.EndParallelize(wg)
	lib.EndTimer(round)

	// If the tree node is the root then protocol returns.
	if p.IsRoot() {
		log.Lvl1(p.ServerIdentity(), " completed key switching.")
		result := make([]lib.FilteredResponse, len(keySwitchingTarget.DataKey))
		for i, v := range keySwitchingTarget.DataKey {
			result[i] = v.Response
		}
		/*
			timeN := time.Since(start)
			filename := "/home/unlynx/go/src/unlynx/services/timeSwitch"
			f, err := os.OpenFile(filename, os.O_APPEND|os.O_WRONLY, 0600)
			if err != nil {
				panic(err)
			}

			defer f.Close()

			if _, err = f.WriteString(timeN.String() + "\n"); err != nil {
				panic(err)
			}*/
		p.ExecTime += time.Since(startT)
		p.FeedbackChannel <- result
	} else {
		log.Lvl1(p.ServerIdentity(), " carried on key switching on ", len(keySwitchingTarget.DataKey), " .")
		sendingNoBytes(p, &keySwitchingTarget.KeySwitchedCipherMessage)
	}

	return nil
}

// sendToNext sends the message msg to the next node in the circuit based on the next TreeNode in Tree.List() If not visited yet.
// If the message already visited the next node, doesn't send and returns false. Otherwise, return true.
func (p *KeySwitchingNoByteProtocol) sendToNext(msg interface{}) {
	err := p.SendTo(p.nextNodeInCircuit, msg)
	if err != nil {
		log.Lvl1(p.Name(), " has an error sending a message: ", err)
	}
}

// sending sends KeySwitchedCipherBytes messages
func sendingNoBytes(p *KeySwitchingNoByteProtocol, kscm *KeySwitchedCipherMessage) {
	//data, l1, l2, l4, l5, l6 := kscm.ToBytes()
	//p.sendToNext(&KSCBLengthMessage{l1, l2, l4, l5, l6})
	p.sendToNext(kscm)
}
