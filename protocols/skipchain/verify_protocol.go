// The verify topology protocol permits the cothority to collectively check the block to ensure that the block
// to be added to the topology skipchain is correct.
// It uses the tree structure of the cothority. The root sends down an aggregation trigger message. The leafs
// respond with their local result and other nodes aggregate what they receive before forwarding the
// aggregation result up the tree until the root can produce the final result.

package protocols

import (
	"errors"

	"bytes"
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/crypto"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/dedis/onet.v1/network"
	"medblock/service/topology"
)

// VerifyBlockProtocolName is the registered name for the verify block protocol.
const VerifyBlockProtocolName = "VerifyBlock"

func init() {
	network.RegisterMessage(BlockMessage{})
	network.RegisterMessage(BlockVerifMessage{})
	onet.GlobalProtocolRegister(VerifyBlockProtocolName, NewVerifyBlockProtocol)
}

// Messages
//______________________________________________________________________________________________________________________

// VerifyData is the list of nodes (public keys) that accepted the block (are willing to sign on it).
type VerifyData struct {
	List []*network.ServerIdentity
}

// BlockMessage identifies the message containing the block that is propagated to the remaining nodes
type BlockMessage struct {
	Block []byte
}

// BlockAndAnswer contains the block and and answer (whether the node accepts it or not). A signature using the node's
// public key is then created over the hash of this struct
type BlockAndAnswer struct {
	Block  []byte
	Answer bool
}

// BlockVerifMessage identifies the message that contains the hash of the block and a signature over that hash (to
// verify the authenticity of the sender)
type BlockVerifMessage struct {
	Answer    bool
	Hash      []byte
	Signature crypto.SchnorrSig
	PubKey    abstract.Point
}

// Structs
//______________________________________________________________________________________________________________________

// blockMessageStruct is the block message structure
type blockMessageStruct struct {
	*onet.TreeNode
	BlockMessage
}

// blockVerifMessageStruct is the a block verif message structure
type blockVerifMessageStruct struct {
	*onet.TreeNode
	BlockVerifMessage
}

// Protocol
//______________________________________________________________________________________________________________________

// VerifyBlockProtocol performs a verification round for the addition of a new topology block.
type VerifyBlockProtocol struct {
	*onet.TreeNodeInstance

	// Protocol feedback channel
	FeedbackChannel chan VerifyData

	// Protocol communication channels
	BlockChannel      chan blockMessageStruct
	BlockVerifChannel chan blockVerifMessageStruct

	// Protocol state data
	TargetBlock []byte
}

// NewVerifyBlockProtocol initializes the protocol instance.
func NewVerifyBlockProtocol(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	instance := &VerifyBlockProtocol{
		TreeNodeInstance: n,
		FeedbackChannel:  make(chan VerifyData),
	}

	if err := instance.RegisterChannel(&instance.BlockChannel); err != nil {
		return nil, errors.New("couldn't register data reference channel: " + err.Error())
	}

	if err := instance.RegisterChannel(&instance.BlockVerifChannel); err != nil {
		return nil, errors.New("couldn't register data reference channel: " + err.Error())
	}

	return instance, nil
}

// Start is called at the root to begin the execution of the protocol.
func (p *VerifyBlockProtocol) Start() error {
	listNodesAccept := make([]*network.ServerIdentity, 0)

	accept, err := chooseVerifFunction(p.TargetBlock)
	if err != nil {
		return nil
	}

	if accept {
		log.LLvl1("Node", p.ServerIdentity(), "accepted to sign the block")
		listNodesAccept = append(listNodesAccept, p.ServerIdentity())
	}

	p.Broadcast(&BlockMessage{Block: p.TargetBlock})

	numberNodes := p.Tree().Size() - 1
	i := 0
	for i < numberNodes {
		m := <-p.BlockVerifChannel
		i++

		valid := crypto.VerifySchnorr(network.Suite, m.PubKey, m.Hash, m.Signature)

		//Get the hash of the block and answer to verify signature
		h, err := hashBlockAndAnswer(p.TargetBlock, m.Answer)
		if err != nil {
			return err
		}

		if valid == nil {
			if bytes.Compare(m.Hash, h) == 0 && m.Answer == true {
				log.LLvl1("Node", m.ServerIdentity, "accepted to sign the block")
				listNodesAccept = append(listNodesAccept, m.ServerIdentity)
			}
		}

	}

	p.FeedbackChannel <- VerifyData{List: listNodesAccept}

	return nil
}

// Dispatch is called at each node and handle incoming messages.
func (p *VerifyBlockProtocol) Dispatch() error {
	m := <-p.BlockChannel

	accept, err := chooseVerifFunction(m.BlockMessage.Block)
	if err != nil {
		return nil
	}

	h, signature, err := signBlockAndAnswer(m.BlockMessage.Block, accept, p.Private())
	if err != nil {
		return nil
	}

	response := BlockVerifMessage{
		Answer:    accept,
		Hash:      h,
		Signature: *signature,
		PubKey:    p.Public(),
	}

	p.SendTo(p.Root(), &response)
	// Now we can add more verification functions depending on the block :D

	return nil
}

func chooseVerifFunction(block []byte) (bool, error) {
	mType, message, err := network.Unmarshal(block)
	if err != nil {
		return false, err
	}

	var accept bool
	if mType.Equal(network.MessageType(topology.StateTopology{})) {
		stBlock := message.(*topology.StateTopology)
		accept, err = verifyTopologyBlock(stBlock)
	}

	if err != nil {
		return false, err
	}

	return accept, nil
}

// verifyTopologyBlock verifies if the block makes sense and accepts or rejects it
func verifyTopologyBlock(st *topology.StateTopology) (bool, error) {
	return true, nil
}

func signBlockAndAnswer(block []byte, answer bool, private abstract.Scalar) ([]byte, *crypto.SchnorrSig, error) {
	h, err := hashBlockAndAnswer(block, answer)

	signature, err := crypto.SignSchnorr(network.Suite, private, h)
	if err != nil {
		log.Fatal("Could not sign hash of block")
		return nil, nil, err
	}

	return h, &signature, nil
}

func hashBlockAndAnswer(block []byte, answer bool) ([]byte, error) {
	h, err := crypto.HashBytes(network.Suite.Hash(), block)
	if err != nil {
		log.Fatal("Could not hash block")
		return nil, err
	}

	if answer == true {
		h = append(h, byte(1))
	} else {
		h = append(h, byte(0))
	}

	return h, nil
}
