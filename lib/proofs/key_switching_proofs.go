package libunlynxproofs

import (
	"github.com/dedis/kyber"
	"github.com/dedis/kyber/proof"
	"github.com/dedis/onet/log"
	"github.com/lca1/unlynx/lib"
	"sync"
)

// SwitchKeyProof proof for key switching
type SwitchKeyProof struct {
	Proof []byte
	b2    kyber.Point
}

// PublishedSwitchKeyProof contains all infos about proofs for key switching of a ciphervector
type PublishedSwitchKeyProof struct {
	Skp        []SwitchKeyProof
	VectBefore libunlynx.CipherVector
	VectAfter  libunlynx.CipherVector
	K          kyber.Point
	Q          kyber.Point
}

// createPredicateKeySwitch creates predicate for key switching proof
func createPredicateKeySwitch() (predicate proof.Predicate) {
	// For ZKP
	log1 := proof.Rep("c1", "ri", "B")
	log2 := proof.Rep("K", "k", "B")

	// Two-secret representation: prove c = kiB1 + siB2
	rep := proof.Rep("c2", "k", "b2", "ri", "Q")

	// and-predicate: prove that a = kiB1, b = siB2 and c = a + b
	and := proof.And(log1, log2)
	and = proof.And(and, rep)
	predicate = proof.And(and)

	return
}

// SwitchKeyProofCreation creates proof for key switching on 1 ciphertext
func SwitchKeyProofCreation(cBef, cAft libunlynx.CipherText, newRandomness, k kyber.Scalar, originEphemKey, q kyber.Point) SwitchKeyProof {
	predicate := createPredicateKeySwitch()

	B := libunlynx.SuiTe.Point().Base()
	c1 := libunlynx.SuiTe.Point().Sub(cAft.K, cBef.K)
	c2 := libunlynx.SuiTe.Point().Sub(cAft.C, cBef.C)
	b2 := libunlynx.SuiTe.Point().Neg(originEphemKey)

	K := libunlynx.SuiTe.Point().Mul(k, libunlynx.SuiTe.Point().Base())

	sval := map[string]kyber.Scalar{"k": k, "ri": newRandomness}
	pval := map[string]kyber.Point{"B": B, "K": K, "Q": q, "b2": b2, "c2": c2, "c1": c1}

	prover := predicate.Prover(libunlynx.SuiTe, sval, pval, nil) // computes: commitment, challenge, response
	Proof, err := proof.HashProve(libunlynx.SuiTe, "proofTest", prover)

	if err != nil {
		log.Fatal("---------Prover:", err.Error())
	}

	return SwitchKeyProof{Proof: Proof, b2: b2}

}

// VectorSwitchKeyProofCreation creates proof for key switching on 1 ciphervector
func VectorSwitchKeyProofCreation(vBef, vAft libunlynx.CipherVector, newRandomnesses []kyber.Scalar, k kyber.Scalar, originEphemKey []kyber.Point, q kyber.Point) []SwitchKeyProof {
	result := make([]SwitchKeyProof, len(vBef))
	var wg sync.WaitGroup
	if libunlynx.PARALLELIZE {
		for i := 0; i < len(vBef); i = i + libunlynx.VPARALLELIZE {
			wg.Add(1)
			go func(i int) {
				for j := 0; j < libunlynx.VPARALLELIZE && (j+i < len(vBef)); j++ {
					result[i+j] = SwitchKeyProofCreation(vBef[i+j], vAft[i+j], newRandomnesses[i+j], k, originEphemKey[i+j], q)
				}
				defer wg.Done()
			}(i)

		}
		wg.Wait()
	} else {
		for i, v := range vBef {
			result[i] = SwitchKeyProofCreation(v, vAft[i], newRandomnesses[i], k, originEphemKey[i], q)
		}
	}
	return result
}

// SwitchKeyCheckProof checks one proof of key switching
func SwitchKeyCheckProof(cp SwitchKeyProof, K, Q kyber.Point, cBef, cAft libunlynx.CipherText) bool {
	predicate := createPredicateKeySwitch()
	B := libunlynx.SuiTe.Point().Base()
	c1 := libunlynx.SuiTe.Point().Sub(cAft.K, cBef.K)
	c2 := libunlynx.SuiTe.Point().Sub(cAft.C, cBef.C)

	pval := map[string]kyber.Point{"B": B, "K": K, "Q": Q, "b2": cp.b2, "c2": c2, "c1": c1}
	verifier := predicate.Verifier(libunlynx.SuiTe, pval)
	if err := proof.HashVerify(libunlynx.SuiTe, "proofTest", verifier, cp.Proof); err != nil {
		log.Error("---------Verifier:", err.Error())
		return false
	}

	return true
}

// PublishedSwitchKeyCheckProof checks published proofs of key switching
func PublishedSwitchKeyCheckProof(psp PublishedSwitchKeyProof) bool {
	for i, v := range psp.Skp {
		if !SwitchKeyCheckProof(v, psp.K, psp.Q, psp.VectBefore[i], psp.VectAfter[i]) {
			return false
		}
	}
	return true
}
