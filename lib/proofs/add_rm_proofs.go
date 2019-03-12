package libunlynxproofs

import (
	"github.com/lca1/unlynx/lib"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/proof"
	"go.dedis.ch/onet/v3/log"
	"sync"
)

// AddRmProof proof for adding/removing a server operations
type AddRmProof struct {
	Proof []byte
	RB    kyber.Point
}

// PublishedAddRmProof contains all infos about proofs for adding/removing operations on a ciphervector
type PublishedAddRmProof struct {
	Arp        []AddRmProof
	VectBefore []libunlynx.CipherText
	VectAfter  []libunlynx.CipherText
	Krm        kyber.Point
	ToAdd      bool
}

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

// AddRmProofCreation creates proof for add/rm server protocol on 1 ciphertext
func AddRmProofCreation(cBef, cAft libunlynx.CipherText, k kyber.Scalar, toAdd bool) AddRmProof {
	predicate := createPredicateAddRm()

	B := libunlynx.SuiTe.Point().Base()
	c2 := libunlynx.SuiTe.Point()
	if toAdd {
		c2 = libunlynx.SuiTe.Point().Sub(cAft.C, cBef.C)
	} else {
		c2 = libunlynx.SuiTe.Point().Sub(cBef.C, cAft.C)
	}

	rB := cBef.K

	K := libunlynx.SuiTe.Point().Mul(k, libunlynx.SuiTe.Point().Base())

	sval := map[string]kyber.Scalar{"k": k}
	pval := map[string]kyber.Point{"B": B, "Krm": K, "c2": c2, "rB": rB}

	prover := predicate.Prover(libunlynx.SuiTe, sval, pval, nil) // computes: commitment, challenge, response
	Proof, err := proof.HashProve(libunlynx.SuiTe, "proofTest", prover)

	if err != nil {
		log.Fatal("---------Prover:", err.Error())
	}

	return AddRmProof{Proof: Proof, RB: rB}

}

// VectorAddRmProofCreation creates proof for add/rm server protocol on 1 ciphervector
func VectorAddRmProofCreation(vBef, vAft []libunlynx.CipherText, k kyber.Scalar, toAdd bool) []AddRmProof {
	var wg sync.WaitGroup
	result := make([]AddRmProof, len(vBef))

	if libunlynx.PARALLELIZE {
		var mutexBf sync.Mutex
		for i := 0; i < len(vBef); i += libunlynx.VPARALLELIZE {
			wg.Add(1)
			go func(i int) {
				for j := 0; j < libunlynx.VPARALLELIZE && (i+j) < len(vBef); j++ {
					proofAux := AddRmProofCreation(vBef[i+j], vAft[i+j], k, toAdd)

					mutexBf.Lock()
					result[i+j] = proofAux
					mutexBf.Unlock()
				}
				defer wg.Done()
			}(i)
		}
		wg.Wait()
	} else {
		for i, v := range vBef {
			result[i] = AddRmProofCreation(v, vAft[i], k, toAdd)
		}
	}
	return result
}

// AddRmCheckProof checks one rm/add proof
func AddRmCheckProof(cp AddRmProof, K kyber.Point, cBef, cAft libunlynx.CipherText, toAdd bool) bool {
	predicate := createPredicateAddRm()
	B := libunlynx.SuiTe.Point().Base()
	c2 := libunlynx.SuiTe.Point()
	if toAdd {
		c2 = libunlynx.SuiTe.Point().Sub(cAft.C, cBef.C)
	} else {
		c2 = libunlynx.SuiTe.Point().Sub(cBef.C, cAft.C)
	}

	pval := map[string]kyber.Point{"B": B, "Krm": K, "c2": c2, "rB": cBef.K}
	verifier := predicate.Verifier(libunlynx.SuiTe, pval)
	if err := proof.HashVerify(libunlynx.SuiTe, "proofTest", verifier, cp.Proof); err != nil {
		log.Error("---------Verifier:", err.Error())
		return false
	}

	log.LLvl1("Proof verified")

	return true
}

// PublishedAddRmCheckProof checks published add/rm protocol proofs
func PublishedAddRmCheckProof(parp PublishedAddRmProof) bool {
	counter := 0
	for i, v := range parp.Arp {
		if !AddRmCheckProof(v, parp.Krm, parp.VectBefore[i], parp.VectAfter[i], parp.ToAdd) {
			return false
		}
		counter++
	}
	return true
}
