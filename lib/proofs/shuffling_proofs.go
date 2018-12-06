package libunlynxproofs

import (
	"sync"

	"github.com/dedis/kyber"
	"github.com/dedis/kyber/proof"
	"github.com/dedis/kyber/shuffle"
	"github.com/dedis/onet/log"
	"github.com/lca1/unlynx/lib"
	"github.com/lca1/unlynx/lib/shuffle"
)

// Structs
//______________________________________________________________________________________________________________________

// PublishedShufflingProof contains all infos about proofs for shuffling of a ciphervector
type PublishedShufflingProof struct {
	OriginalList []libunlynx.CipherVector
	ShuffledList []libunlynx.CipherVector
	G            kyber.Point
	H            kyber.Point
	HashProof    []byte
}

// PublishedShufflingProofBytes is the bytes equivalent of PublishedShufflingProof
type PublishedShufflingProofBytes struct {
	OriginalList       *[]byte
	OriginalListLength *[]byte
	ShuffledList       *[]byte
	ShuffledListLength *[]byte
	G                  *[]byte
	H                  *[]byte
	HashProof          []byte
}

// ShufflingProofCreation creates a shuffle proof in its publishable version
func ShufflingProofCreation(originalList, shuffledList []libunlynx.CipherVector, g, h kyber.Point, beta [][]kyber.Scalar, pi []int) PublishedShufflingProof {
	prf := shuffleProofCreation(originalList, shuffledList, beta, pi, h)
	return PublishedShufflingProof{originalList, shuffledList, g, h, prf}
}

// shuffleProofCreation creates a proof for one shuffle on a list of CipherVector
func shuffleProofCreation(inputList, outputList []libunlynx.CipherVector, beta [][]kyber.Scalar, pi []int, h kyber.Point) []byte {
	e := inputList[0].CipherVectorTag(h)
	k := len(inputList)
	// compress data for each line (each list) into one element
	Xhat := make([]kyber.Point, k)
	Yhat := make([]kyber.Point, k)
	XhatBar := make([]kyber.Point, k)
	YhatBar := make([]kyber.Point, k)

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

// checkShuffleProof verifies a shuffling proof
func checkShuffleProof(g, h kyber.Point, Xhat, Yhat, XhatBar, YhatBar []kyber.Point, prf []byte) bool {
	verifier := shuffle.Verifier(libunlynx.SuiTe, g, h, Xhat, Yhat, XhatBar, YhatBar)
	err := proof.HashVerify(libunlynx.SuiTe, "PairShuffle", verifier, prf)
	if err != nil {
		log.LLvl1(err)
		log.LLvl1("-----------verify failed (with XharBar)")
		return false
	}

	return true
}

// CompressProcessResponseMultiple applies shuffling compression to 2 list of process responses corresponding to input and output of shuffling
func CompressProcessResponseMultiple(inputList, outputList []libunlynx.ProcessResponse, i int, e []kyber.Scalar, Xhat, XhatBar, Yhat, YhatBar []kyber.Point) {
	wg := libunlynx.StartParallelize(2)
	go func() {
		defer wg.Done()
		tmp := CompressProcessResponse(inputList[i], e)
		Xhat[i] = tmp.K
		Yhat[i] = tmp.C
	}()
	go func() {
		defer wg.Done()
		tmpBar := CompressProcessResponse(outputList[i], e)
		XhatBar[i] = tmpBar.K
		YhatBar[i] = tmpBar.C
	}()
	libunlynx.EndParallelize(wg)

}

// ComputeE computes e used in a shuffle proof. Computation based on a public seed.
func ComputeE(index int, cv libunlynx.ProcessResponse, seed []byte, aggrAttrLen, grpAttrLen int) kyber.Scalar {
	var dataC []byte
	var dataK []byte

	randomCipher := libunlynx.SuiTe.XOF(seed)
	if index < aggrAttrLen {
		dataC, _ = cv.AggregatingAttributes[index].C.MarshalBinary()
		dataK, _ = cv.AggregatingAttributes[index].K.MarshalBinary()

	} else if index < aggrAttrLen+grpAttrLen {
		dataC, _ = cv.GroupByEnc[index-aggrAttrLen].C.MarshalBinary()
		dataK, _ = cv.GroupByEnc[index-aggrAttrLen].K.MarshalBinary()
	} else {
		dataC, _ = cv.WhereEnc[index-aggrAttrLen-grpAttrLen].C.MarshalBinary()
		dataK, _ = cv.WhereEnc[index-aggrAttrLen-grpAttrLen].K.MarshalBinary()
	}

	randomCipher.Write(dataC)
	randomCipher.Write(dataK)

	return libunlynx.SuiTe.Scalar().Pick(randomCipher)
}

// compressCipherVector (slice of ciphertexts) into one ciphertext
func compressCipherVector(ciphervector libunlynx.CipherVector, e []kyber.Scalar) libunlynx.CipherText {
	k := len(ciphervector)

	// check that e and cipher vectors have the same size
	if len(e) != k {
		panic("e is not the right size!")
	}

	ciphertext := *libunlynx.NewCipherText()
	for i := 0; i < k; i++ {
		aux := libunlynx.NewCipherText()
		aux.MulCipherTextbyScalar(ciphervector[i], e[i])
		ciphertext.Add(ciphertext, *aux)
	}
	return ciphertext
}

// CompressProcessResponse applies shuffling compression to a process response
func CompressProcessResponse(processResponse libunlynx.ProcessResponse, e []kyber.Scalar) libunlynx.CipherText {
	m := len(processResponse.GroupByEnc)
	n := len(processResponse.WhereEnc)
	o := len(processResponse.AggregatingAttributes)

	// check size of e
	if len(e) != m+n+o {
		//+o
		panic("e is not the same size as the list")
	}

	sum := *libunlynx.NewCipherText()
	var sum1, sum2, sum3 libunlynx.CipherText
	if libunlynx.PARALLELIZE {
		wg := libunlynx.StartParallelize(3)
		go func() {
			sum1 = compressCipherVector(processResponse.GroupByEnc, e[0:m])
			defer wg.Done()
		}()
		go func() {
			sum2 = compressCipherVector(processResponse.WhereEnc, e[m:m+n])
			defer wg.Done()
		}()
		go func() {
			sum3 = compressCipherVector(processResponse.AggregatingAttributes, e[m+n:m+n+o])
			defer wg.Done()
		}()
		libunlynx.EndParallelize(wg)
	} else {
		sum1 = compressCipherVector(processResponse.GroupByEnc, e[0:m])
		sum2 = compressCipherVector(processResponse.WhereEnc, e[m:m+n])
		sum3 = compressCipherVector(processResponse.AggregatingAttributes, e[m+n:m+n+o])
	}

	sum.Add(sum1, sum2)
	sum.Add(sum, sum3)

	return sum
}

// CompressListProcessResponse applies shuffling compression to a list of process responses
func CompressListProcessResponse(processResponses []libunlynx.ProcessResponse, e []kyber.Scalar) ([]kyber.Point, []kyber.Point) {
	xC := make([]kyber.Point, len(processResponses))
	xK := make([]kyber.Point, len(processResponses))

	wg := libunlynx.StartParallelize(len(processResponses))
	for i, v := range processResponses {
		if libunlynx.PARALLELIZE {
			go func(i int, v libunlynx.ProcessResponse) {
				tmp := CompressProcessResponse(v, e)
				xK[i] = tmp.K
				xC[i] = tmp.C
				defer wg.Done()
			}(i, v)
		} else {
			tmp := CompressProcessResponse(v, e)
			xK[i] = tmp.K
			xC[i] = tmp.C
		}
	}

	libunlynx.EndParallelize(wg)
	return xK, xC
}

// Marshal
//______________________________________________________________________________________________________________________

// ToBytes transforms PublishedShufflingProof to bytes
func (psp *PublishedShufflingProof) ToBytes() PublishedShufflingProofBytes {
	pspb := PublishedShufflingProofBytes{}

	wg := libunlynx.StartParallelize(3)

	// convert OriginalList
	mutex1 := sync.Mutex{}
	go func(data []libunlynx.CipherVector) {
		defer wg.Done()
		tmp, tmpLength := libunlynx.ArrayCipherVectorToBytes(data)

		mutex1.Lock()
		pspb.OriginalList = &tmp
		pspb.OriginalListLength = &tmpLength
		mutex1.Unlock()
	}(psp.OriginalList)

	// convert ShuffledList
	mutex2 := sync.Mutex{}
	go func(data []libunlynx.CipherVector) {
		defer wg.Done()
		tmp, tmpLength := libunlynx.ArrayCipherVectorToBytes(data)

		mutex2.Lock()
		pspb.ShuffledList = &tmp
		pspb.ShuffledListLength = &tmpLength
		mutex2.Unlock()
	}(psp.ShuffledList)

	// convert 'the rest'
	go func(G, H kyber.Point, HashProof []byte) {
		defer wg.Done()

		tmpGBytes := libunlynx.AbstractPointsToBytes([]kyber.Point{G})
		pspb.G = &tmpGBytes
		tmpHBytes := libunlynx.AbstractPointsToBytes([]kyber.Point{H})
		pspb.H = &tmpHBytes

		pspb.HashProof = psp.HashProof
	}(psp.G, psp.H, psp.HashProof)

	libunlynx.EndParallelize(wg)

	return pspb
}

// FromBytes transforms bytes back to PublishedShufflingProof
func (psp *PublishedShufflingProof) FromBytes(pspb PublishedShufflingProofBytes) {
	psp.OriginalList = libunlynx.FromBytesToArrayCipherVector(*pspb.OriginalList, *pspb.OriginalListLength)
	psp.ShuffledList = libunlynx.FromBytesToArrayCipherVector(*pspb.ShuffledList, *pspb.ShuffledListLength)
	psp.G = libunlynx.FromBytesToAbstractPoints(*pspb.G)[0]
	psp.H = libunlynx.FromBytesToAbstractPoints(*pspb.H)[0]
	psp.HashProof = pspb.HashProof
}

/*
// CompressBeta applies shuffling compression to a list of list of scalars (beta)
func CompressBeta(beta [][]kyber.Scalar, e []kyber.Scalar) []kyber.Scalar {
	k := len(beta)
	NQ := len(beta[0])
	betaCompressed := make([]kyber.Scalar, k)
	wg := libunlynx.StartParallelize(k)
	for i := 0; i < k; i++ {
		betaCompressed[i] = libunlynx.SuiTe.Scalar().Zero()
		if libunlynx.PARALLELIZE {
			go func(i int) {
				defer wg.Done()
				for j := 0; j < NQ; j++ {
					tmp := libunlynx.SuiTe.Scalar().Mul(beta[i][j], e[j])
					betaCompressed[i] = libunlynx.SuiTe.Scalar().Add(betaCompressed[i], tmp)
				}
			}(i)
		} else {
			for j := 0; j < NQ; j++ {
				tmp := libunlynx.SuiTe.Scalar().Mul(beta[i][j], e[j])
				betaCompressed[i] = libunlynx.SuiTe.Scalar().Add(betaCompressed[i], tmp)
			}
		}

	}
	libunlynx.EndParallelize(wg)

	return betaCompressed
}*/

/*import (
	"github.com/dedis/kyber"
	"github.com/dedis/kyber/proof"
	"github.com/dedis/kyber/shuffle"
	"github.com/dedis/onet/log"
	"github.com/lca1/unlynx/lib"
	"github.com/lca1/unlynx/lib/shuffle"
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
}*/
