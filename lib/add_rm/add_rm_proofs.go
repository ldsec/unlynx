package libunlynxaddrm

import (
	"fmt"
	"math"
	"sync"

	"github.com/ldsec/unlynx/lib"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/proof"
	"go.dedis.ch/onet/v3/log"
)

// PublishedAddRmProof contains a proof for adding/removing a server
type PublishedAddRmProof struct {
	Proof []byte
	CtBef libunlynx.CipherText
	CtAft libunlynx.CipherText
	RB    kyber.Point
}

// PublishedAddRmListProof contains multiple proofs for adding/removing a server
type PublishedAddRmListProof struct {
	List  []PublishedAddRmProof
	Krm   kyber.Point
	ToAdd bool
}

// ADD/REMOVE proofs
//______________________________________________________________________________________________________________________

// createPredicateAddRm creates predicate for add/rm server protocol
func createPredicateAddRm() (predicate proof.Predicate) {
	// For ZKP
	log1 := proof.Rep("Krm", "k", "B")

	// Two-secret representation: prove c = kiB1 + siB2
	rep := proof.Rep("c2", "k", "rB")

	// and-predicate: prove that a = kiB1, b = siB2 and c = a + b
	and := proof.And(log1, rep)
	predicate = proof.And(and)

	return
}

// AddRmProofCreation creates proof for add/rm server protocol for one ciphertext
func AddRmProofCreation(cBef, cAft libunlynx.CipherText, K kyber.Point, k kyber.Scalar, toAdd bool) (PublishedAddRmProof, error) {
	predicate := createPredicateAddRm()

	B := libunlynx.SuiTe.Point().Base()
	c2 := libunlynx.SuiTe.Point()
	if toAdd {
		c2 = libunlynx.SuiTe.Point().Sub(cAft.C, cBef.C)
	} else {
		c2 = libunlynx.SuiTe.Point().Sub(cBef.C, cAft.C)
	}

	rB := cBef.K

	sval := map[string]kyber.Scalar{"k": k}
	pval := map[string]kyber.Point{"B": B, "Krm": K, "c2": c2, "rB": rB}

	prover := predicate.Prover(libunlynx.SuiTe, sval, pval, nil) // computes: commitment, challenge, response
	proofTmp, err := proof.HashProve(libunlynx.SuiTe, "proofTest", prover)

	if err != nil {
		return PublishedAddRmProof{}, fmt.Errorf("---------prover: %v", err)
	}

	return PublishedAddRmProof{Proof: proofTmp, CtBef: cBef, CtAft: cAft, RB: rB}, nil
}

// AddRmListProofCreation creates proof for add/rm server protocol for one ciphervector
func AddRmListProofCreation(vBef, vAft libunlynx.CipherVector, K kyber.Point, k kyber.Scalar, toAdd bool) (PublishedAddRmListProof, error) {
	result := PublishedAddRmListProof{}
	result.List = make([]PublishedAddRmProof, len(vBef))

	var wg sync.WaitGroup
	var err error
	mutex := sync.Mutex{}
	for i := 0; i < len(vBef); i += libunlynx.VPARALLELIZE {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < libunlynx.VPARALLELIZE && (i+j) < len(vBef); j++ {
				proofAux, tmpErr := AddRmProofCreation(vBef[i+j], vAft[i+j], K, k, toAdd)
				if tmpErr != nil {
					mutex.Lock()
					err = tmpErr
					mutex.Unlock()
					return
				}
				result.List[i+j] = proofAux
			}
		}(i)
	}
	wg.Wait()

	if err != nil {
		return PublishedAddRmListProof{}, err
	}

	result.Krm = K
	result.ToAdd = toAdd
	return result, nil
}

// AddRmProofVerification verifies an add/rm proof
func AddRmProofVerification(cp PublishedAddRmProof, K kyber.Point, toAdd bool) bool {
	predicate := createPredicateAddRm()
	B := libunlynx.SuiTe.Point().Base()
	c2 := libunlynx.SuiTe.Point()
	if toAdd {
		c2 = libunlynx.SuiTe.Point().Sub(cp.CtAft.C, cp.CtBef.C)
	} else {
		c2 = libunlynx.SuiTe.Point().Sub(cp.CtBef.C, cp.CtAft.C)
	}

	pval := map[string]kyber.Point{"B": B, "Krm": K, "c2": c2, "rB": cp.CtBef.K}
	verifier := predicate.Verifier(libunlynx.SuiTe, pval)
	if err := proof.HashVerify(libunlynx.SuiTe, "proofTest", verifier, cp.Proof); err != nil {
		log.Error("---------Verifier:", err.Error())
		return false
	}
	log.Lvl1("Proof verified")
	return true
}

// AddRmListProofVerification verifies multiple add/rm proofs
func AddRmListProofVerification(parp PublishedAddRmListProof, percent float64) bool {
	nbrProofsToVerify := int(math.Ceil(percent * float64(len(parp.List))))
	results := make([]bool, nbrProofsToVerify)

	var wg sync.WaitGroup
	for i := 0; i < len(parp.List); i += libunlynx.VPARALLELIZE {
		wg.Add(1)
		go func(i int, krm kyber.Point, toadd bool) {
			defer wg.Done()
			for j := 0; j < libunlynx.VPARALLELIZE && (i+j) < len(parp.List); j++ {
				results[i+j] = AddRmProofVerification(parp.List[i+j], krm, toadd)
			}
		}(i, parp.Krm, parp.ToAdd)
	}
	wg.Wait()

	finalResult := true
	for _, v := range results {
		finalResult = finalResult && v
	}
	return finalResult
}
