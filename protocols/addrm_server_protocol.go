// Package protocolsunlynx implements the addrm_server protocol.
// It permits to removes/adds a conode from the collective authority or, in other words,
// it removes/adds a server's contribution from the original ciphertexts.
package protocolsunlynx

import (
	"sync"

	"github.com/lca1/unlynx/lib/add_rm"

	"github.com/dedis/kyber"
	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
	"github.com/lca1/unlynx/lib"
)

// AddRmServerProtocolName is the registered name for the local aggregation protocol.
const AddRmServerProtocolName = "AddRmServer"

func init() {
	if _, err := onet.GlobalProtocolRegister(AddRmServerProtocolName, NewAddRmProtocol); err != nil {
		log.Fatal("Error registering <AddRmServerProtocol>:", err)
	}
}

// Protocol
//______________________________________________________________________________________________________________________

// AddRmServerProtocol is a struct holding the state of a protocol instance.
type AddRmServerProtocol struct {
	*onet.TreeNodeInstance

	// Protocol feedback channel
	FeedbackChannel chan []libunlynx.CipherText

	// Protocol state data
	TargetOfTransformation []libunlynx.CipherText
	KeyToRm                kyber.Scalar
	Proofs                 bool
	Add                    bool
}

// NewAddRmProtocol is constructor of add/rm protocol instances.
func NewAddRmProtocol(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	pvp := &AddRmServerProtocol{
		TreeNodeInstance: n,
		FeedbackChannel:  make(chan []libunlynx.CipherText),
	}

	return pvp, nil
}

var finalResultAddrm = make(chan []libunlynx.CipherText)

// Start is called at the root to start the execution of the Add/Rm protocol.
func (p *AddRmServerProtocol) Start() error {

	log.Lvl1(p.Name(), "starts a server adding/removing Protocol")
	roundComput := libunlynx.StartTimer(p.Name() + "_AddRmServer(PROTOCOL)")

	result := make([]libunlynx.CipherText, len(p.TargetOfTransformation))
	result = changeEncryption(p.TargetOfTransformation, p.KeyToRm, p.Add)
	libunlynx.EndTimer(roundComput)

	roundProof := libunlynx.StartTimer(p.Name() + "_AddRmServer(PROOFS)")
	proofs := libunlynxaddrm.PublishedAddRmListProof{}
	if p.Proofs {
		ktopub := libunlynx.SuiTe.Point().Mul(p.KeyToRm, libunlynx.SuiTe.Point().Base())
		proofs = libunlynxaddrm.AddRmListProofCreation(p.TargetOfTransformation, result, ktopub, p.KeyToRm, p.Add)
	}

	libunlynx.EndTimer(roundProof)

	roundProof = libunlynx.StartTimer(p.Name() + "_AddRmServer(PROOFSVerif)")

	if p.Proofs && len(proofs.List) == 0 {
		log.Fatal("Something went wrong during the creation of the add/rm proofs")
	}
	libunlynxaddrm.AddRmListProofVerification(proofs, 1.0)

	libunlynx.EndTimer(roundProof)

	finalResultAddrm <- result
	return nil
}

// Dispatch is called on each node. It waits for incoming messages and handle them.
func (p *AddRmServerProtocol) Dispatch() error {
	defer p.Done()

	aux := <-finalResultAddrm
	p.FeedbackChannel <- aux
	return nil
}

func changeEncryption(cipherTexts []libunlynx.CipherText, serverAddRmKey kyber.Scalar, toAdd bool) []libunlynx.CipherText {
	result := make([]libunlynx.CipherText, len(cipherTexts))

	var wg sync.WaitGroup
	for i := 0; i < len(cipherTexts); i += libunlynx.VPARALLELIZE {
		wg.Add(1)
		go func(i int) {
			for j := 0; j < libunlynx.VPARALLELIZE && (i+j) < len(cipherTexts); j++ {
				result[i+j] = changeEncryptionKeyCipherTexts(cipherTexts[i+j], serverAddRmKey, toAdd)
			}
			defer wg.Done()
		}(i)
	}
	wg.Wait()

	return result
}

func changeEncryptionKeyCipherTexts(cipherText libunlynx.CipherText, serverAddRmKey kyber.Scalar, toAdd bool) libunlynx.CipherText {
	tmp := libunlynx.SuiTe.Point().Mul(serverAddRmKey, cipherText.K)
	result := libunlynx.CipherText{}
	result.K = cipherText.K
	if toAdd {
		result.C = libunlynx.SuiTe.Point().Add(cipherText.C, tmp)
	} else {
		result.C = libunlynx.SuiTe.Point().Sub(cipherText.C, tmp)
	}
	return result
}
