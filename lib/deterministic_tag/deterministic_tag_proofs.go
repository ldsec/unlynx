package libunlynxdetertag

import (
	"math"
	"reflect"
	"sync"

	"github.com/dedis/kyber"
	"github.com/dedis/kyber/proof"
	"github.com/dedis/onet/log"
	"github.com/lca1/unlynx/lib"
)

// PublishedDDTCreationProof contains all the info about proofs for the deterministic tagging of one ciphertext (creation)
type PublishedDDTCreationProof struct {
	Proof       []byte
	Ciminus11Si kyber.Point
	CTbef       libunlynx.CipherText
	CTaft       libunlynx.CipherText
}

// PublishedDDTCreationListProof contains all the info about proofs for the deterministic tagging of one sequence of ciphertexts (creation)
type PublishedDDTCreationListProof struct {
	Dcp []PublishedDDTCreationProof
	K   kyber.Point
	SB  kyber.Point
}

// PublishedDDTAdditionProof contains all the info about proofs for the deterministic tagging (addition)
type PublishedDDTAdditionProof struct {
	C1    kyber.Point
	C2    kyber.Point
	R     kyber.Point
	Proof []byte
}

// PublishedDDTAdditionListProof contains all the info about multiple proofs for the deterministic tagging (addition)
type PublishedDDTAdditionListProof struct {
	Pdap []PublishedDDTAdditionProof
}

// DETERMINISTIC TAG proofs
//______________________________________________________________________________________________________________________

// Creation
//______________________________________________________________________________________________________________________

// createPredicateDeterministicTagCr creates predicate for deterministic tagging proof
func createPredicateDeterministicTagCr() (predicate proof.Predicate) {
	// For ZKP
	log1 := proof.Rep("ci1", "s", "ciminus11")
	log2 := proof.Rep("K", "k", "B")
	log3 := proof.Rep("SB", "s", "B")

	// Two-secret representation: prove c = kiB1 + siB2
	rep := proof.Rep("ci2", "s", "ciminus12", "k", "ciminus11Si")

	// and-predicate: prove that a = kiB1, b = siB2 and c = a + b
	and := proof.And(log1, log2)
	and = proof.And(and, rep)
	and = proof.And(and, log3)
	predicate = proof.And(and)

	return
}

// DeterministicTagCrProofCreation creates a deterministic tag proof for one ciphertext
func DeterministicTagCrProofCreation(ctBef, ctAft libunlynx.CipherText, K kyber.Point, k, s kyber.Scalar) PublishedDDTCreationProof {
	predicate := createPredicateDeterministicTagCr()

	ci1 := ctAft.K
	ciminus11 := ctBef.K
	ci2 := ctAft.C
	ciminus12 := ctBef.C
	ciminus11Si := libunlynx.SuiTe.Point().Neg(libunlynx.SuiTe.Point().Mul(s, ciminus11))
	B := libunlynx.SuiTe.Point().Base()

	sval := map[string]kyber.Scalar{"k": k, "s": s}
	pval := map[string]kyber.Point{"B": B, "K": K, "ciminus11Si": ciminus11Si, "ciminus12": ciminus12, "ciminus11": ciminus11, "ci2": ci2, "ci1": ci1}

	prover := predicate.Prover(libunlynx.SuiTe, sval, pval, nil) // computes: commitment, challenge, response
	Proof, err := proof.HashProve(libunlynx.SuiTe, "proofTest", prover)
	if err != nil {
		log.Fatal("---------Prover:", err.Error())
	}

	return PublishedDDTCreationProof{Proof: Proof, Ciminus11Si: ciminus11Si, CTbef: ctBef, CTaft: ctAft}
}

// DeterministicTagCrListProofCreation creates a list of deterministic tag proofs (multiple ciphertexts)
func DeterministicTagCrListProofCreation(vBef, vAft libunlynx.CipherVector, K kyber.Point, k, s kyber.Scalar) PublishedDDTCreationListProof {
	listProofs := PublishedDDTCreationListProof{}
	listProofs.Dcp = make([]PublishedDDTCreationProof, len(vBef))

	var wg sync.WaitGroup

	for i := 0; i < len(vBef); i += libunlynx.VPARALLELIZE {
		wg.Add(1)
		go func(i int) {
			for j := 0; j < libunlynx.VPARALLELIZE && (j+i < len(vBef)); j++ {
				listProofs.Dcp[i+j] = DeterministicTagCrProofCreation(vBef[i+j], vAft[i+j], K, k, s)
			}
			defer wg.Done()
		}(i)

	}
	wg.Wait()

	listProofs.K = K
	listProofs.SB = libunlynx.SuiTe.Point().Mul(s, libunlynx.SuiTe.Point().Base())

	return listProofs
}

// DeterministicTagCrProofVerification verifies a deterministic tag proof for one ciphertext
func DeterministicTagCrProofVerification(prf PublishedDDTCreationProof, K, SB kyber.Point) bool {
	predicate := createPredicateDeterministicTagCr()
	B := libunlynx.SuiTe.Point().Base()
	ci1 := prf.CTaft.K
	ciminus11 := prf.CTbef.K
	ci2 := prf.CTaft.C
	ciminus12 := prf.CTbef.C

	pval := map[string]kyber.Point{"B": B, "K": K, "ciminus11Si": prf.Ciminus11Si, "ciminus12": ciminus12, "ciminus11": ciminus11, "ci2": ci2, "ci1": ci1, "SB": SB}
	verifier := predicate.Verifier(libunlynx.SuiTe, pval)
	if err := proof.HashVerify(libunlynx.SuiTe, "proofTest", verifier, prf.Proof); err != nil {
		log.Error("---------Verifier:", err.Error())
		return false
	}

	return true
}

// DeterministicTagCrListProofVerification verifies a list of deterministic tag proofs, if one is wrong, returns false
func DeterministicTagCrListProofVerification(pdclp PublishedDDTCreationListProof, percent float64) bool {
	nbrProofsToVerify := int(math.Ceil(percent * float64(len(pdclp.Dcp))))

	wg := libunlynx.StartParallelize(nbrProofsToVerify)
	results := make([]bool, nbrProofsToVerify)
	for i := 0; i < nbrProofsToVerify; i++ {
		go func(i int, v PublishedDDTCreationProof) {
			defer wg.Done()
			results[i] = DeterministicTagCrProofVerification(v, pdclp.K, pdclp.SB)
		}(i, pdclp.Dcp[i])

	}
	libunlynx.EndParallelize(wg)
	finalResult := true
	for _, v := range results {
		finalResult = finalResult && v
	}
	return finalResult
}

// Addition
//______________________________________________________________________________________________________________________

// createPredicateDeterministicTagAddition creates predicate for deterministic tagging addition proof
func createPredicateDeterministicTagAddition() (predicate proof.Predicate) {
	// For ZKP
	log1 := proof.Rep("c2", "s", "B")

	predicate = proof.And(log1)

	return
}

// DeterministicTagAdditionProofCreation creates proof for deterministic tagging addition on 1 kyber point
func DeterministicTagAdditionProofCreation(c1 kyber.Point, s kyber.Scalar, c2 kyber.Point, r kyber.Point) PublishedDDTAdditionProof {
	predicate := createPredicateDeterministicTagAddition()
	B := libunlynx.SuiTe.Point().Base()
	sval := map[string]kyber.Scalar{"s": s}
	pval := map[string]kyber.Point{"B": B, "c1": c1, "c2": c2, "r": r}

	prover := predicate.Prover(libunlynx.SuiTe, sval, pval, nil) // computes: commitment, challenge, response
	Proof, err := proof.HashProve(libunlynx.SuiTe, "proofTest", prover)
	if err != nil {
		log.Fatal("---------Prover:", err.Error())
	}

	return PublishedDDTAdditionProof{Proof: Proof, C1: c1, C2: c2, R: r}
}

// DeterministicTagAdditionProofCreation creates proof for deterministic tagging addition on multiple kyber points
func DeterministicTagAdditionListProofCreation(c1List []kyber.Point, sList []kyber.Scalar, c2List []kyber.Point, rList []kyber.Point) PublishedDDTAdditionListProof {
	nbrProofsToCreate := len(c1List)

	listProofs := PublishedDDTAdditionListProof{}
	listProofs.Pdap = make([]PublishedDDTAdditionProof, nbrProofsToCreate)

	var wg sync.WaitGroup

	for i := 0; i < nbrProofsToCreate; i += libunlynx.VPARALLELIZE {
		wg.Add(1)
		go func(i int, c1 kyber.Point, s kyber.Scalar, c2 kyber.Point, r kyber.Point) {
			for j := 0; j < libunlynx.VPARALLELIZE && (j+i < nbrProofsToCreate); j++ {
				listProofs.Pdap[i+j] = DeterministicTagAdditionProofCreation(c1, s, c2, r)
			}
			defer wg.Done()
		}(i, c1List[i], sList[i], c2List[i], rList[i])

	}
	wg.Wait()

	return listProofs
}

// DeterministicTagAdditionProofVerification verifies a deterministic tag addition proof
func DeterministicTagAdditionProofVerification(psap PublishedDDTAdditionProof) bool {
	predicate := createPredicateDeterministicTagAddition()
	B := libunlynx.SuiTe.Point().Base()
	pval := map[string]kyber.Point{"B": B, "c1": psap.C1, "c2": psap.C2, "r": psap.R}
	verifier := predicate.Verifier(libunlynx.SuiTe, pval)
	partProof := false
	if err := proof.HashVerify(libunlynx.SuiTe, "proofTest", verifier, psap.Proof); err != nil {
		log.Error("---------Verifier:", err.Error())
		return false
	}

	partProof = true

	cv := libunlynx.SuiTe.Point().Add(psap.C1, psap.C2)
	return partProof && reflect.DeepEqual(cv, psap.R)
}

// DeterministicTagAdditionListProofVerification verifies multiple deterministic tag addition proofs
func DeterministicTagAdditionListProofVerification(pdalp PublishedDDTAdditionListProof, percent float64) bool {
	nbrProofsToVerify := int(math.Ceil(percent * float64(len(pdalp.Pdap))))

	wg := libunlynx.StartParallelize(nbrProofsToVerify)
	results := make([]bool, nbrProofsToVerify)
	for i := 0; i < nbrProofsToVerify; i++ {
		go func(i int, v PublishedDDTAdditionProof) {
			defer wg.Done()
			results[i] = DeterministicTagAdditionProofVerification(v)
		}(i, pdalp.Pdap[i])

	}
	libunlynx.EndParallelize(wg)
	finalResult := true
	for _, v := range results {
		finalResult = finalResult && v
	}
	return finalResult

}
