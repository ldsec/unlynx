package proofs

import (
    "sync"
    "github.com/dedis/kyber/proof"
    "github.com/lca1/unlynx/lib"
    "github.com/dedis/kyber"
    "github.com/dedis/onet/log"
)

// DeterministicTaggingProof proof for tag creation operation
type DeterministicTaggingProof struct {
    Proof       []byte
    ciminus11Si kyber.Point
    SB          kyber.Point
}

// PublishedDeterministicTaggingProof contains all infos about proofs for deterministic tagging of a ciphervector
type PublishedDeterministicTaggingProof struct {
    Dhp        []DeterministicTaggingProof
    VectBefore libunlynx.CipherVector
    VectAfter  libunlynx.CipherVector
    K          kyber.Point
    SB         kyber.Point
}

// createPredicateDeterministicTag creates predicate for deterministic tagging proof
func createPredicateDeterministicTag() (predicate proof.Predicate) {
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

// DeterministicTagProofCreation creates proof for deterministic tagging protocol on 1 ciphertext
func DeterministicTagProofCreation(cBef, cAft libunlynx.CipherText, k, s kyber.Scalar) DeterministicTaggingProof {
    predicate := createPredicateDeterministicTag()

    ci1 := cAft.K
    ciminus11 := cBef.K
    ci2 := cAft.C
    ciminus12 := cBef.C
    ciminus11Si := libunlynx.SuiTe.Point().Neg(libunlynx.SuiTe.Point().Mul(s, ciminus11))
    K := libunlynx.SuiTe.Point().Mul(k, libunlynx.SuiTe.Point().Base())
    B := libunlynx.SuiTe.Point().Base()
    SB := libunlynx.SuiTe.Point().Mul(s, B)

    sval := map[string]kyber.Scalar{"k": k, "s": s}
    pval := map[string]kyber.Point{"B": B, "K": K, "ciminus11Si": ciminus11Si, "ciminus12": ciminus12, "ciminus11": ciminus11, "ci2": ci2, "ci1": ci1}

    prover := predicate.Prover(libunlynx.SuiTe, sval, pval, nil) // computes: commitment, challenge, response
    Proof, err := proof.HashProve(libunlynx.SuiTe, "proofTest", prover)
    if err != nil {
        log.Fatal("---------Prover:", err.Error())
    }

    return DeterministicTaggingProof{Proof: Proof, ciminus11Si: ciminus11Si, SB: SB}

}

// VectorDeterministicTagProofCreation creates proof for deterministic tagging protocol on 1 ciphervector
func VectorDeterministicTagProofCreation(vBef, vAft libunlynx.CipherVector, s, k kyber.Scalar) []DeterministicTaggingProof {
    result := make([]DeterministicTaggingProof, len(vBef))
    var wg sync.WaitGroup
    if libunlynx.PARALLELIZE {
        for i := 0; i < len(vBef); i += libunlynx.VPARALLELIZE {
            wg.Add(1)
            go func(i int) {
                for j := 0; j < libunlynx.VPARALLELIZE && (j+i < len(vBef)); j++ {
                    result[i+j] = DeterministicTagProofCreation(vBef[i+j], vAft[i+j], k, s)
                }
                defer wg.Done()
            }(i)

        }
        wg.Wait()
    } else {
        for i, v := range vBef {
            result[i] = DeterministicTagProofCreation(v, vAft[i], k, s)
        }
    }

    return result
}

// DeterministicTagCheckProof checks one deterministic tagging proof
func DeterministicTagCheckProof(cp DeterministicTaggingProof, K kyber.Point, cBef, cAft libunlynx.CipherText) bool {
    predicate := createPredicateDeterministicTag()
    B := libunlynx.SuiTe.Point().Base()
    ci1 := cAft.K
    ciminus11 := cBef.K
    ci2 := cAft.C
    ciminus12 := cBef.C

    pval := map[string]kyber.Point{"B": B, "K": K, "ciminus11Si": cp.ciminus11Si, "ciminus12": ciminus12, "ciminus11": ciminus11, "ci2": ci2, "ci1": ci1, "SB": cp.SB}
    verifier := predicate.Verifier(libunlynx.SuiTe, pval)
    if err := proof.HashVerify(libunlynx.SuiTe, "proofTest", verifier, cp.Proof); err != nil {
        log.Error("---------Verifier:", err.Error())
        return false
    }

    return true
}

// PublishedDeterministicTaggingCheckProof checks published deterministic tagging proofs
func PublishedDeterministicTaggingCheckProof(php PublishedDeterministicTaggingProof) (bool, kyber.Point) {
    if php.SB == nil {
        php.SB = php.Dhp[0].SB
    }

    for i, v := range php.Dhp {
        if !DeterministicTagCheckProof(v, php.K, php.VectBefore[i], php.VectAfter[i]) || !v.SB.Equal(php.SB) {
            return false, nil
        }
    }
    return true, php.SB
}
