package libunlynxaddrm

import (
	"math"
	"sync"

	"github.com/dedis/kyber"
	"github.com/dedis/kyber/proof"
	"github.com/dedis/onet/log"
	"github.com/lca1/unlynx/lib"
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
	Arp   []PublishedAddRmProof
	Krm   kyber.Point
	ToAdd bool
}

// Add/Remove protocol proofs
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
func AddRmProofCreation(cBef, cAft libunlynx.CipherText, K kyber.Point, k kyber.Scalar, toAdd bool) PublishedAddRmProof {
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
	Proof, err := proof.HashProve(libunlynx.SuiTe, "proofTest", prover)

	if err != nil {
		log.Fatal("---------Prover:", err.Error())
	}

	return PublishedAddRmProof{Proof: Proof, CtBef: cBef, CtAft: cAft, RB: rB}
}

// AddRmListProofCreation creates proof for add/rm server protocol for one ciphervector
func AddRmListProofCreation(vBef, vAft libunlynx.CipherVector, K kyber.Point, k kyber.Scalar, toAdd bool) PublishedAddRmListProof {
	var wg sync.WaitGroup
	result := PublishedAddRmListProof{}
	result.Arp = make([]PublishedAddRmProof, len(vBef))

	for i := 0; i < len(vBef); i += libunlynx.VPARALLELIZE {
		wg.Add(1)
		go func(i int) {
			for j := 0; j < libunlynx.VPARALLELIZE && (i+j) < len(vBef); j++ {
				proofAux := AddRmProofCreation(vBef[i+j], vAft[i+j], K, k, toAdd)
				result.Arp[i+j] = proofAux
			}
			defer wg.Done()
		}(i)
	}
	wg.Wait()

	result.Krm = K
	result.ToAdd = toAdd

	return result
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

	log.LLvl1("Proof verified")

	return true
}

// AddRmListProofVerification verifies multiple add/rm proofs
func AddRmListProofVerification(parp PublishedAddRmListProof, percent float64) bool {
	nbrProofsToVerify := int(math.Ceil(percent * float64(len(parp.Arp))))

	wg := libunlynx.StartParallelize(nbrProofsToVerify)
	results := make([]bool, nbrProofsToVerify)
	for i, v := range parp.Arp {
		go func(idx int, v PublishedAddRmProof, krm kyber.Point, toadd bool) {
			defer wg.Done()
			results[idx] = AddRmProofVerification(v, krm, toadd)
		}(i, v, parp.Krm, parp.ToAdd)
	}
	libunlynx.EndParallelize(wg)

	finalResult := true
	for _, v := range results {
		finalResult = finalResult && v
	}
	return finalResult
}
