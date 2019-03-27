package libunlynxkeyswitch

import (
	"math"
	"sync"

	"github.com/dedis/kyber"
	"github.com/dedis/kyber/proof"
	"github.com/dedis/onet/log"
	"github.com/lca1/unlynx/lib"
)

// Structs
//______________________________________________________________________________________________________________________

// PublishedKSProof contains all infos about proofs for key switching
type PublishedKSProof struct {
	Proof []byte
	K     kyber.Point
	ViB   kyber.Point
	Ks2   kyber.Point
	RbNeg kyber.Point
	Q     kyber.Point
}

// PublishedKSProofBytes is the 'bytes' equivalent of PublishedKSProof
type PublishedKSProofBytes struct {
	Proof         []byte
	KVibKs2RbNegQ []byte
}

// PublishedKSListProof is a list of PublishedKSProof
type PublishedKSListProof struct {
	List []PublishedKSProof
}

// PublishedKSListProofBytes is the 'bytes' equivalent of PublishedKSListProof
type PublishedKSListProofBytes struct {
	List []PublishedKSProofBytes
}

// KEY SWITCH proofs
//______________________________________________________________________________________________________________________

func createPredicateKeySwitch() (predicate proof.Predicate) {
	// For ZKP
	log1 := proof.Rep("viB", "vi", "B")
	log2 := proof.Rep("K", "k", "B")

	// Two-secret representation: prove c = kiB1 + siB2
	rep := proof.Rep("ks2", "k", "rBNeg", "vi", "Q")

	// and-predicate: prove that a = kiB1, b = siB2 and c = a + b
	and := proof.And(log1, log2)
	and = proof.And(and, rep)
	predicate = proof.And(and)

	return
}

// KeySwitchProofCreation creates a key switch proof for one ciphertext
func KeySwitchProofCreation(K, Q kyber.Point, k kyber.Scalar, viB, ks2, rBNeg kyber.Point, vi kyber.Scalar) PublishedKSProof {
	predicate := createPredicateKeySwitch()
	sval := map[string]kyber.Scalar{"vi": vi, "k": k}
	pval := map[string]kyber.Point{"K": K, "viB": viB, "ks2": ks2, "rBNeg": rBNeg, "Q": Q}

	prover := predicate.Prover(libunlynx.SuiTe, sval, pval, nil) // computes: commitment, challenge, response
	Proof, err := proof.HashProve(libunlynx.SuiTe, "proofTest", prover)
	if err != nil {
		log.Fatal("---------Prover:", err.Error())
	}

	return PublishedKSProof{Proof: Proof, K: K, ViB: viB, Ks2: ks2, RbNeg: rBNeg, Q: Q}
}

// KeySwitchListProofCreation creates a list of key switch proofs (multiple ciphertexts)
func KeySwitchListProofCreation(K, Q kyber.Point, k kyber.Scalar, ks2s, rBNegs []kyber.Point, vis []kyber.Scalar) PublishedKSListProof {
	viBs := make([]kyber.Point, len(vis))

	var wg1 sync.WaitGroup
	for i := 0; i < len(viBs); i += libunlynx.VPARALLELIZE {
		wg1.Add(1)
		go func(i int) {
			for j := 0; j < libunlynx.VPARALLELIZE && (j+i < len(viBs)); j++ {
				viBs[i+j] = libunlynx.SuiTe.Point().Mul(vis[i+j], libunlynx.SuiTe.Point().Base())
			}
			defer wg1.Done()
		}(i)

	}
	wg1.Wait()

	plop := PublishedKSListProof{}
	plop.List = make([]PublishedKSProof, len(viBs))

	var wg2 sync.WaitGroup
	for i := 0; i < len(viBs); i += libunlynx.VPARALLELIZE {
		wg2.Add(1)
		go func(i int, Q kyber.Point, k kyber.Scalar) {
			for j := 0; j < libunlynx.VPARALLELIZE && (j+i < len(viBs)); j++ {
				plop.List[i+j] = KeySwitchProofCreation(K, Q, k, viBs[i+j], ks2s[i+j], rBNegs[i+j], vis[i+j])
			}
			defer wg2.Done()
		}(i, Q, k)

	}
	wg2.Wait()

	return plop
}

// KeySwitchProofVerification verifies a key switch proof for one ciphertext
func KeySwitchProofVerification(pop PublishedKSProof) bool {
	predicate := createPredicateKeySwitch()
	pval := map[string]kyber.Point{"K": pop.K, "viB": pop.ViB, "ks2": pop.Ks2, "rBNeg": pop.RbNeg, "Q": pop.Q}
	verifier := predicate.Verifier(libunlynx.SuiTe, pval)

	if err := proof.HashVerify(libunlynx.SuiTe, "proofTest", verifier, pop.Proof); err != nil {
		log.Error("---------Verifier:", err.Error())
		return false
	}

	return true
}

// KeySwitchListProofVerification verifies a list of key switch proofs, if one is wrong, returns false
func KeySwitchListProofVerification(pkslp PublishedKSListProof, percent float64) bool {
	nbrProofsToVerify := int(math.Ceil(percent * float64(len(pkslp.List))))
	results := make([]bool, nbrProofsToVerify)

	var wg sync.WaitGroup
	for i := 0; i < nbrProofsToVerify; i += libunlynx.VPARALLELIZE {
		wg.Add(1)
		go func(i int) {
			for j := 0; j < libunlynx.VPARALLELIZE && (i+j) < nbrProofsToVerify; j++ {
				results[i+j] = KeySwitchProofVerification(pkslp.List[i+j])
			}
			defer wg.Done()
		}(i)
	}
	wg.Wait()

	finalResult := true
	for _, v := range results {
		finalResult = finalResult && v
	}
	return finalResult
}

// Marshal
//______________________________________________________________________________________________________________________

// ToBytes converts PublishedKSProof to bytes
func (pksp *PublishedKSProof) ToBytes() PublishedKSProofBytes {
	popb := PublishedKSProofBytes{}
	popb.Proof = pksp.Proof
	popb.KVibKs2RbNegQ = libunlynx.AbstractPointsToBytes([]kyber.Point{pksp.K, pksp.ViB, pksp.Ks2, pksp.RbNeg, pksp.Q})
	return popb
}

// FromBytes converts back bytes to PublishedKSProof
func (pksp *PublishedKSProof) FromBytes(pkspb PublishedKSProofBytes) {
	pksp.Proof = pkspb.Proof
	KVibKs2RbnegQ := libunlynx.FromBytesToAbstractPoints(pkspb.KVibKs2RbNegQ)
	pksp.K = KVibKs2RbnegQ[0]
	pksp.ViB = KVibKs2RbnegQ[1]
	pksp.Ks2 = KVibKs2RbnegQ[2]
	pksp.RbNeg = KVibKs2RbnegQ[3]
	pksp.Q = KVibKs2RbnegQ[4]
}

// ToBytes converts PublishedKSListProof to bytes
func (pkslp *PublishedKSListProof) ToBytes() PublishedKSListProofBytes {
	pkslpb := PublishedKSListProofBytes{}

	prsB := make([]PublishedKSProofBytes, len(pkslp.List))
	wg := libunlynx.StartParallelize(len(pkslp.List))
	for i, pksp := range pkslp.List {
		go func(index int, pksp PublishedKSProof) {
			defer wg.Done()
			prsB[index] = pksp.ToBytes()
		}(i, pksp)
	}
	libunlynx.EndParallelize(wg)
	pkslpb.List = prsB
	return pkslpb
}

// FromBytes converts bytes back to PublishedKSListProof
func (pkslp *PublishedKSListProof) FromBytes(pkslpb PublishedKSListProofBytes) {
	prs := make([]PublishedKSProof, len(pkslpb.List))
	wg := libunlynx.StartParallelize(len(pkslpb.List))
	for i, pkspb := range pkslpb.List {
		go func(index int, pkspb PublishedKSProofBytes) {
			defer wg.Done()
			tmp := PublishedKSProof{}
			tmp.FromBytes(pkspb)
			prs[index] = tmp
		}(i, pkspb)
	}
	libunlynx.EndParallelize(wg)
	pkslp.List = prs
}
