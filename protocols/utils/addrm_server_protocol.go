// Package protocolsunlynxutils implements the addrm_server protocol.
// It permits to removes/adds a conode from the collective authority or, in other words,
// it removes/adds a server's contribution from the original ciphertexts.
package protocolsunlynxutils

import (
	"fmt"
	"sync"
	"time"

	"github.com/ldsec/unlynx/lib"
	"github.com/ldsec/unlynx/lib/add_rm"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
)

// AddRmServerProtocolName is the registered name for the local aggregation protocol.
const AddRmServerProtocolName = "AddRmServer"

func init() {
	_, err := onet.GlobalProtocolRegister(AddRmServerProtocolName, NewAddRmProtocol)
	log.ErrFatal(err, "Failed to register the <AddRmServer> protocol:")

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
		var err error
		proofs, err = libunlynxaddrm.AddRmListProofCreation(p.TargetOfTransformation, result, ktopub, p.KeyToRm, p.Add)
		if err != nil {
			return err
		}
	}

	libunlynx.EndTimer(roundProof)

	roundProof = libunlynx.StartTimer(p.Name() + "_AddRmServer(PROOFSVerif)")

	if p.Proofs && len(proofs.List) == 0 {
		return fmt.Errorf("something went wrong during the creation of the add/rm proofs")
	}
	libunlynxaddrm.AddRmListProofVerification(proofs, 1.0)

	libunlynx.EndTimer(roundProof)

	finalResultAddrm <- result
	return nil
}

// Dispatch is called on each node. It waits for incoming messages and handle them.
func (p *AddRmServerProtocol) Dispatch() error {
	defer p.Done()

	var finalResultMessage []libunlynx.CipherText
	select {
	case finalResultMessage = <-finalResultAddrm:
	case <-time.After(libunlynx.TIMEOUT):
		return fmt.Errorf(p.ServerIdentity().String() + " didn't get the <finalResultMessage> on time")
	}

	p.FeedbackChannel <- finalResultMessage
	return nil
}

func changeEncryption(cipherTexts []libunlynx.CipherText, serverAddRmKey kyber.Scalar, toAdd bool) []libunlynx.CipherText {
	result := make([]libunlynx.CipherText, len(cipherTexts))

	var wg sync.WaitGroup
	for i := 0; i < len(cipherTexts); i += libunlynx.VPARALLELIZE {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < libunlynx.VPARALLELIZE && (i+j) < len(cipherTexts); j++ {
				result[i+j] = changeEncryptionKeyCipherTexts(cipherTexts[i+j], serverAddRmKey, toAdd)
			}
		}(i)
	}
	wg.Wait()

	return result
}

func changeEncryptionKeyCipherTexts(cipherText libunlynx.CipherText, serverAddRmKey kyber.Scalar, toAdd bool) libunlynx.CipherText {
	result := libunlynx.CipherText{}
	result.K = cipherText.K
	if toAdd {
		result.C = libunlynx.SuiTe.Point().Add(cipherText.C, libunlynx.SuiTe.Point().Mul(serverAddRmKey, cipherText.K))
	} else {
		result.C = libunlynx.SuiTe.Point().Sub(cipherText.C, libunlynx.SuiTe.Point().Mul(serverAddRmKey, cipherText.K))
	}
	return result
}
