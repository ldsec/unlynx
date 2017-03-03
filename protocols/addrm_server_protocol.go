// Package protocols contains the adding/removing protocol which permits to change the encryption of data.
// It allows to remove/add a server contribution to the encryption of ciphertexts.
// We assume that the server joining/leaving the cothority participates in the process.
package protocols

import (
	"github.com/JoaoAndreSa/MedCo/lib"
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/dedis/onet.v1/network"
	"sync"
)

// AddRmServerProtocolName is the registered name for the local aggregation protocol.
const AddRmServerProtocolName = "AddRmServer"

func init() {
	onet.GlobalProtocolRegister(AddRmServerProtocolName, NewAddRmProtocol)
}

// Protocol
//______________________________________________________________________________________________________________________

// AddRmServerProtocol is a struct holding the state of a protocol instance.
type AddRmServerProtocol struct {
	*onet.TreeNodeInstance

	// Protocol feedback channel
	FeedbackChannel chan []lib.ClientResponse

	// Protocol state data
	TargetOfTransformation []lib.ClientResponse
	KeyToRm                abstract.Scalar
	Proofs                 bool
	Add                    bool
}

// NewAddRmProtocol is constructor of add/rm protocol instances.
func NewAddRmProtocol(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	pvp := &AddRmServerProtocol{
		TreeNodeInstance: n,
		FeedbackChannel:  make(chan []lib.ClientResponse),
	}

	return pvp, nil
}

var finalResultAddrm = make(chan []lib.ClientResponse)

func changeEncryptionKeyVector(cv lib.CipherVector, serverAddRmKey abstract.Scalar, toAdd bool) lib.CipherVector {
	result := make(lib.CipherVector, len(cv))
	for j, w := range cv {
		tmp := network.Suite.Point().Mul(w.K, serverAddRmKey)
		result[j].K = w.K
		if toAdd {
			result[j].C = network.Suite.Point().Add(w.C, tmp)

		} else {
			result[j].C = network.Suite.Point().Sub(w.C, tmp)
		}
	}
	return result
}

// Start is called at the root to start the execution of the Add/Rm protocol.
func (p *AddRmServerProtocol) Start() error {

	log.Lvl1(p.Name(), "starts a server adding/removing Protocol")
	roundComput := lib.StartTimer(p.Name() + "_AddRmServer(PROTOCOL)")

	result := make([]lib.ClientResponse, len(p.TargetOfTransformation))

	wg := lib.StartParallelize(len(p.TargetOfTransformation))
	var mutexToT sync.Mutex
	for i, v := range p.TargetOfTransformation {
		if lib.PARALLELIZE {
			go func(i int, v lib.ClientResponse) {
				defer wg.Done()

				mutexToT.Lock()
				keyToRm := p.KeyToRm
				add := p.Add
				mutexToT.Unlock()

				grpAttributes := v.GroupingAttributesClear
				aggrAttributes := changeEncryptionKeyVector(v.AggregatingAttributes, keyToRm, add)
				probaGrpAttributes := changeEncryptionKeyVector(v.ProbaGroupingAttributesEnc, keyToRm, add)

				mutexToT.Lock()
				result[i].GroupingAttributesClear = grpAttributes
				result[i].AggregatingAttributes = aggrAttributes
				result[i].ProbaGroupingAttributesEnc = probaGrpAttributes
				mutexToT.Unlock()
			}(i, v)
		} else {
			result[i].AggregatingAttributes = changeEncryptionKeyVector(v.AggregatingAttributes, p.KeyToRm, p.Add)
			result[i].ProbaGroupingAttributesEnc = changeEncryptionKeyVector(v.ProbaGroupingAttributesEnc, p.KeyToRm, p.Add)
		}

	}

	lib.EndParallelize(wg)
	lib.EndTimer(roundComput)

	roundProof := lib.StartTimer(p.Name() + "_AddRmServer(PROOFS)")
	pubs := make([]lib.PublishedAddRmProof, 0)
	if p.Proofs {
		wg := lib.StartParallelize(len(result))
		var mutexCR sync.Mutex
		for i, v := range result {
			if lib.PARALLELIZE {
				go func(i int, v lib.ClientResponse) {
					defer wg.Done()

					mutexCR.Lock()
					targetAggregatingAttributes := p.TargetOfTransformation[i].AggregatingAttributes
					probaAggregatingAttributes := p.TargetOfTransformation[i].ProbaGroupingAttributesEnc
					keyToRm := p.KeyToRm
					mutexCR.Unlock()

					prfAggr := lib.VectorAddRmProofCreation(targetAggregatingAttributes, v.AggregatingAttributes, p.KeyToRm, p.Add)
					prfGrp := lib.VectorAddRmProofCreation(probaAggregatingAttributes, v.ProbaGroupingAttributesEnc, p.KeyToRm, p.Add)
					ktopub := network.Suite.Point().Mul(network.Suite.Point().Base(), keyToRm)
					pub1 := lib.PublishedAddRmProof{Arp: prfAggr, VectBefore: targetAggregatingAttributes, VectAfter: v.AggregatingAttributes, Krm: ktopub, ToAdd: p.Add}
					pub2 := lib.PublishedAddRmProof{Arp: prfGrp, VectBefore: probaAggregatingAttributes, VectAfter: v.ProbaGroupingAttributesEnc, Krm: ktopub, ToAdd: p.Add}

					mutexCR.Lock()
					pubs = append(pubs, pub1, pub2)
					mutexCR.Unlock()
				}(i, v)

			} else {
				prfAggr := lib.VectorAddRmProofCreation(p.TargetOfTransformation[i].AggregatingAttributes, v.AggregatingAttributes, p.KeyToRm, p.Add)
				prfGrp := lib.VectorAddRmProofCreation(p.TargetOfTransformation[i].ProbaGroupingAttributesEnc, v.ProbaGroupingAttributesEnc, p.KeyToRm, p.Add)
				ktopub := network.Suite.Point().Mul(network.Suite.Point().Base(), p.KeyToRm)
				pub1 := lib.PublishedAddRmProof{Arp: prfAggr, VectBefore: p.TargetOfTransformation[i].AggregatingAttributes, VectAfter: v.AggregatingAttributes, Krm: ktopub, ToAdd: p.Add}
				pub2 := lib.PublishedAddRmProof{Arp: prfGrp, VectBefore: p.TargetOfTransformation[i].ProbaGroupingAttributesEnc, VectAfter: v.ProbaGroupingAttributesEnc, Krm: ktopub, ToAdd: p.Add}
				pubs = append(pubs, pub1, pub2)
			}

		}
		lib.EndParallelize(wg)
	}

	lib.EndTimer(roundProof)

	roundProof = lib.StartTimer(p.Name() + "_AddRmServer(PROOFSVerif)")
	wg = lib.StartParallelize(len(pubs))
	for _, v := range pubs {
		if lib.PARALLELIZE {
			go func(v lib.PublishedAddRmProof) {
				defer wg.Done()
				lib.PublishedAddRmCheckProof(v)
			}(v)
		} else {
			lib.PublishedAddRmCheckProof(v)
		}

	}
	lib.EndParallelize(wg)
	lib.EndTimer(roundProof)

	finalResultAddrm <- result
	return nil
}

// Dispatch is called on each node. It waits for incoming messages and handle them.
func (p *AddRmServerProtocol) Dispatch() error {
	aux := <-finalResultAddrm
	p.FeedbackChannel <- aux
	return nil
}
