package libunlynxdetertag

import (
	"sync"

	"github.com/dedis/kyber"
	"github.com/lca1/unlynx/lib"
)

// DeterministicTagSequence performs the second step in the distributed deterministic tagging process (cycle round) on a ciphervector.
func DeterministicTagSequence(cv libunlynx.CipherVector, private, secretContrib kyber.Scalar) libunlynx.CipherVector {
	cvNew := libunlynx.NewCipherVector(len(cv))

	var wg sync.WaitGroup
	if libunlynx.PARALLELIZE {
		for i := 0; i < len(cv); i = i + libunlynx.VPARALLELIZE {
			wg.Add(1)
			go func(i int) {
				for j := 0; j < libunlynx.VPARALLELIZE && (j+i < len(cv)); j++ {
					(*cvNew)[i+j] = DeterministicTag(cv[i+j], private, secretContrib)
				}
				defer wg.Done()
			}(i)

		}
		wg.Wait()
	} else {
		for i, ct := range cv {
			(*cvNew)[i] = DeterministicTag(ct, private, secretContrib)
		}
	}

	return *cvNew
}

// DeterministicTag the second step in the distributed deterministic tagging process (the cycle round) on a ciphertext.
func DeterministicTag(ct libunlynx.CipherText, private, secretContrib kyber.Scalar) libunlynx.CipherText {
	//ct(K,C) = (C1i-1, C2i-2)
	//ctNew(K,C) = (C1i,C2i)
	ctNew := libunlynx.NewCipherText()

	//secretContrib = si
	//ct.K = C1i-1
	//C1i = si * C1i-1
	ctNew.K = libunlynx.SuiTe.Point().Mul(secretContrib, ct.K)

	//private = ki
	//contrib = C1i-1*ki
	contrib := libunlynx.SuiTe.Point().Mul(private, ct.K)

	//C2i = si * (C2i-1 - contrib)
	ctNew.C = libunlynx.SuiTe.Point().Sub(ct.C, contrib)
	ctNew.C = libunlynx.SuiTe.Point().Mul(secretContrib, ctNew.C)

	return *ctNew
}

// Representation
//______________________________________________________________________________________________________________________

// CipherVectorToDeterministicTag creates a tag (grouping key) from a cipher vector
func CipherVectorToDeterministicTag(vBef libunlynx.CipherVector, privKey, secContrib kyber.Scalar, K kyber.Point, proofs bool) (libunlynx.GroupingKey, *PublishedDDTCreationListProof) {
	vAft := DeterministicTagSequence(vBef, privKey, secContrib)

	var pdclp PublishedDDTCreationListProof
	if proofs {
		pdclp = DeterministicTagListProofCreation(vBef, vAft, K, privKey, secContrib)
	}

	deterministicGroupAttributes := make(libunlynx.DeterministCipherVector, len(vAft))
	for j, c := range vAft {
		deterministicGroupAttributes[j] = libunlynx.DeterministCipherText{Point: c.C}
	}
	return deterministicGroupAttributes.Key(), &pdclp
}
