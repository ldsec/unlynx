package libunlynxproofs

import (
	"github.com/lca1/unlynx/lib"
	"github.com/lca1/unlynx/lib/shuffle"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/proof"
	"go.dedis.ch/kyber/v3/shuffle"
	"go.dedis.ch/onet/v3/log"
)

// PublishedShufflingProof contains all infos about proofs for shuffling of a ciphervector
type PublishedShufflingProof struct {
	OriginalList []libunlynx.CipherVector
	ShuffledList []libunlynx.CipherVector
	G            kyber.Point
	H            kyber.Point
	HashProof    []byte
}

// ShuffleProofCreation creates a proof for one shuffle on a list of process response
func shuffleProofCreation(inputList, outputList []libunlynx.CipherVector, beta [][]kyber.Scalar, pi []int, h kyber.Point) []byte {
	e := inputList[0].CipherVectorTag(h)
	k := len(inputList)
	// compress data for each line (each list) into one element
	Xhat := make([]kyber.Point, k)
	Yhat := make([]kyber.Point, k)
	XhatBar := make([]kyber.Point, k)
	YhatBar := make([]kyber.Point, k)

	//var betaCompressed []kyber.Scalar
	wg1 := libunlynx.StartParallelize(k)
	for i := 0; i < k; i++ {
		if libunlynx.PARALLELIZE {
			go func(inputList, outputList []libunlynx.CipherVector, i int) {
				defer (*wg1).Done()
				libunlynxshuffle.CompressProcessResponseMultiple(inputList, outputList, i, e, Xhat, XhatBar, Yhat, YhatBar)
			}(inputList, outputList, i)
		} else {
			libunlynxshuffle.CompressProcessResponseMultiple(inputList, outputList, i, e, Xhat, XhatBar, Yhat, YhatBar)
		}
	}
	libunlynx.EndParallelize(wg1)

	betaCompressed := libunlynxshuffle.CompressBeta(beta, e)

	rand := libunlynx.SuiTe.RandomStream()

	// do k-shuffle of ElGamal on the (Xhat,Yhat) and check it
	k = len(Xhat)
	if k != len(Yhat) {
		panic("X,Y vectors have inconsistent lengths")
	}
	ps := shuffle.PairShuffle{}
	ps.Init(libunlynx.SuiTe, k)

	prover := func(ctx proof.ProverContext) error {
		return ps.Prove(pi, nil, h, betaCompressed, Xhat, Yhat, rand, ctx)
	}

	prf, err := proof.HashProve(libunlynx.SuiTe, "PairShuffle", prover)
	if err != nil {
		panic("Shuffle proof failed: " + err.Error())
	}
	return prf
}

// ShufflingProofCreation creates a shuffle proof in its publishable version
func ShufflingProofCreation(originalList, shuffledList []libunlynx.CipherVector, g, h kyber.Point, beta [][]kyber.Scalar, pi []int) PublishedShufflingProof {
	prf := shuffleProofCreation(originalList, shuffledList, beta, pi, h)
	return PublishedShufflingProof{originalList, shuffledList, g, h, prf}
}

// checkShuffleProof verifies a shuffling proof
func checkShuffleProof(g, h kyber.Point, Xhat, Yhat, XhatBar, YhatBar []kyber.Point, prf []byte) bool {
	verifier := shuffle.Verifier(libunlynx.SuiTe, g, h, Xhat, Yhat, XhatBar, YhatBar)
	err := proof.HashVerify(libunlynx.SuiTe, "PairShuffle", verifier, prf)

	if err != nil {
		log.LLvl1("-----------verify failed (with XharBar)")
		return false
	}

	return true
}

// ShufflingProofVerification allows to check a shuffling proof
func ShufflingProofVerification(psp PublishedShufflingProof, seed kyber.Point) bool {
	e := psp.OriginalList[0].CipherVectorTag(seed)
	var x, y, xbar, ybar []kyber.Point
	if libunlynx.PARALLELIZE {
		wg := libunlynx.StartParallelize(2)
		go func() {
			x, y = libunlynxshuffle.CompressListProcessResponse(psp.OriginalList, e)
			defer (*wg).Done()
		}()
		go func() {
			xbar, ybar = libunlynxshuffle.CompressListProcessResponse(psp.ShuffledList, e)
			defer (*wg).Done()
		}()

		libunlynx.EndParallelize(wg)
	} else {
		x, y = libunlynxshuffle.CompressListProcessResponse(psp.OriginalList, e)
		xbar, ybar = libunlynxshuffle.CompressListProcessResponse(psp.ShuffledList, e)
	}

	return checkShuffleProof(psp.G, psp.H, x, y, xbar, ybar, psp.HashProof)
}
