package libunlynxshuffle

import (
	"fmt"
	"math"
	"sync"

	"github.com/ldsec/unlynx/lib"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/proof"
	shuffleKyber "go.dedis.ch/kyber/v3/shuffle"
	"go.dedis.ch/onet/v3/log"
)

// Structs
//______________________________________________________________________________________________________________________

// PublishedShufflingProof contains all infos about proofs for shuffling
type PublishedShufflingProof struct {
	OriginalList []libunlynx.CipherVector
	ShuffledList []libunlynx.CipherVector
	G            kyber.Point
	H            kyber.Point
	HashProof    []byte
}

// PublishedShufflingProofBytes is the 'bytes' equivalent of PublishedShufflingProof
type PublishedShufflingProofBytes struct {
	OriginalList       *[]byte
	OriginalListLength *[]byte
	ShuffledList       *[]byte
	ShuffledListLength *[]byte
	G                  *[]byte
	H                  *[]byte
	HashProof          []byte
}

// PublishedShufflingListProof contains a list of shuffling proofs
type PublishedShufflingListProof struct {
	List []PublishedShufflingProof
}

// SHUFFLE proofs
//______________________________________________________________________________________________________________________

// ShuffleProofCreation creates a shuffle proof
func ShuffleProofCreation(originalList, shuffledList []libunlynx.CipherVector, g, h kyber.Point, beta [][]kyber.Scalar, pi []int) (PublishedShufflingProof, error) {
	e, err := CipherVectorComputeE(h, originalList[0])
	if err != nil {
		return PublishedShufflingProof{}, err
	}

	k := len(originalList)
	// compress data for each line (each list) into one element
	Xhat := make([]kyber.Point, k)
	Yhat := make([]kyber.Point, k)
	XhatBar := make([]kyber.Point, k)
	YhatBar := make([]kyber.Point, k)

	mutex := sync.Mutex{}
	wg1 := libunlynx.StartParallelize(k)
	for i := 0; i < k; i++ {
		go func(inputList, outputList []libunlynx.CipherVector, i int) {
			defer (*wg1).Done()
			tmpErr := compressCipherVectorMultiple(inputList, outputList, i, e, Xhat, XhatBar, Yhat, YhatBar)
			if tmpErr != nil {
				mutex.Lock()
				err = tmpErr
				mutex.Unlock()
				return
			}
		}(originalList, shuffledList, i)
	}
	libunlynx.EndParallelize(wg1)

	if err != nil {
		return PublishedShufflingProof{}, err
	}

	betaCompressed := compressBeta(beta, e)

	rand := libunlynx.SuiTe.RandomStream()

	// do k-shuffle of ElGamal on the (Xhat,Yhat) and check it
	k = len(Xhat)
	if k != len(Yhat) {
		return PublishedShufflingProof{}, fmt.Errorf("X,Y vectors have inconsistent lengths")
	}
	ps := shuffleKyber.PairShuffle{}
	ps.Init(libunlynx.SuiTe, k)

	prover := func(ctx proof.ProverContext) error {
		return ps.Prove(pi, nil, h, betaCompressed, Xhat, Yhat, rand, ctx)
	}

	prf, err := proof.HashProve(libunlynx.SuiTe, "PairShuffle", prover)
	if err != nil {
		return PublishedShufflingProof{}, fmt.Errorf("shuffle proof failed: %v", err)
	}
	return PublishedShufflingProof{originalList, shuffledList, g, h, prf}, nil
}

// ShuffleListProofCreation generates a list of shuffle proofs
func ShuffleListProofCreation(originalList, shuffledList [][]libunlynx.CipherVector, gList, hList []kyber.Point, betaList [][][]kyber.Scalar, piList [][]int) (PublishedShufflingListProof, error) {
	nbrProofsToCreate := len(originalList)

	listProofs := PublishedShufflingListProof{}
	listProofs.List = make([]PublishedShufflingProof, nbrProofsToCreate)

	var err error
	mutex := sync.Mutex{}
	var wg sync.WaitGroup
	for i := 0; i < nbrProofsToCreate; i += libunlynx.VPARALLELIZE {
		wg.Add(1)
		go func(i int, originalList, shuffledList [][]libunlynx.CipherVector, g, h []kyber.Point, beta [][][]kyber.Scalar, pi [][]int) {
			defer wg.Done()
			for j := 0; j < libunlynx.VPARALLELIZE && (j+i < nbrProofsToCreate); j++ {
				var tmpErr error
				listProofs.List[i+j], tmpErr = ShuffleProofCreation(originalList[i+j], shuffledList[i+j], g[i+j], h[i+j], beta[i+j], pi[i+j])
				if tmpErr != nil {
					mutex.Lock()
					err = tmpErr
					mutex.Unlock()
					return
				}
			}
		}(i, originalList, shuffledList, gList, hList, betaList, piList)
	}
	wg.Wait()

	if err != nil {
		return PublishedShufflingListProof{}, err
	}

	return listProofs, nil
}

// ShuffleProofVerification verifies a shuffle proof
func ShuffleProofVerification(psp PublishedShufflingProof, seed kyber.Point) bool {
	e, err := CipherVectorComputeE(seed, psp.OriginalList[0])
	if err != nil {
		log.Error(err)
		log.Lvl1("-----------verify failed (with XhaBar)")
		return false
	}

	var x, y, xbar, ybar []kyber.Point
	mutex := sync.Mutex{}

	wg := libunlynx.StartParallelize(2)
	go func() {
		defer (*wg).Done()
		var tmpErr error
		x, y, tmpErr = compressListCipherVector(psp.OriginalList, e)
		if tmpErr != nil {
			mutex.Lock()
			err = tmpErr
			mutex.Unlock()
			return
		}

	}()
	go func() {
		defer (*wg).Done()
		var tmpErr error
		xbar, ybar, tmpErr = compressListCipherVector(psp.ShuffledList, e)
		if tmpErr != nil {
			mutex.Lock()
			err = tmpErr
			mutex.Unlock()
			return
		}

	}()

	libunlynx.EndParallelize(wg)

	if err != nil {
		log.Error(err)
		log.Lvl1("-----------verify failed (compressListCipherVector)")
		return false
	}

	verifier := shuffleKyber.Verifier(libunlynx.SuiTe, psp.G, psp.H, x, y, xbar, ybar)
	err = proof.HashVerify(libunlynx.SuiTe, "PairShuffle", verifier, psp.HashProof)
	if err != nil {
		log.Error(err)
		log.Lvl1("-----------verify failed (with XhaBar)")
		return false
	}

	return true
}

// ShuffleListProofVerification verifies a list of shuffle proofs
func ShuffleListProofVerification(pslp PublishedShufflingListProof, seed kyber.Point, percent float64) bool {
	nbrProofsToVerify := int(math.Ceil(percent * float64(len(pslp.List))))

	results := make([]bool, nbrProofsToVerify)

	var wg sync.WaitGroup
	for i := 0; i < nbrProofsToVerify; i += libunlynx.VPARALLELIZE {
		wg.Add(1)
		go func(i int, seed kyber.Point) {
			defer wg.Done()
			for j := 0; j < libunlynx.VPARALLELIZE && (i+j) < nbrProofsToVerify; j++ {
				results[i+j] = ShuffleProofVerification(pslp.List[i+j], seed)
			}
		}(i, seed)
	}
	wg.Wait()

	finalResult := true
	for _, v := range results {
		finalResult = finalResult && v
	}
	return finalResult
}

// CipherVectorComputeE computes all the e's for a ciphervector based on a seed h
func CipherVectorComputeE(h kyber.Point, cv libunlynx.CipherVector) ([]kyber.Scalar, error) {
	var err error
	length := len(cv)
	es := make([]kyber.Scalar, length)

	seed, err := h.MarshalBinary()
	if err != nil {
		return nil, err
	}

	mutex := sync.Mutex{}
	var wg sync.WaitGroup
	for i := 0; i < length; i = i + libunlynx.VPARALLELIZE {
		wg.Add(1)
		go func(i int, cv libunlynx.CipherVector) {
			defer wg.Done()
			for j := 0; j < libunlynx.VPARALLELIZE && (j+i < length); j++ {
				e, tmpErr := computeE(i+j, cv, seed)
				if tmpErr != nil {
					mutex.Lock()
					err = tmpErr
					mutex.Unlock()
					return
				}
				es[i+j] = e
			}

		}(i, cv)

	}
	wg.Wait()

	if err != nil {
		return nil, err
	}

	return es, nil
}

// computeE computes e used in a shuffle proof. Computation based on a public seed.
func computeE(index int, cv libunlynx.CipherVector, seed []byte) (kyber.Scalar, error) {
	var dataC []byte
	var dataK []byte

	randomCipher := libunlynx.SuiTe.XOF(seed)

	dataC, err := cv[index].C.MarshalBinary()
	if err != nil {
		return nil, err
	}

	dataK, err = cv[index].K.MarshalBinary()
	if err != nil {
		return nil, err
	}

	if _, err := randomCipher.Write(dataC); err != nil {
		return nil, err
	}
	if _, err := randomCipher.Write(dataK); err != nil {
		return nil, err
	}

	return libunlynx.SuiTe.Scalar().Pick(randomCipher), nil
}

// Compress
//______________________________________________________________________________________________________________________

// compressCipherVector (slice of ciphertexts) into one ciphertext
func compressCipherVector(ciphervector libunlynx.CipherVector, e []kyber.Scalar) (libunlynx.CipherText, error) {
	k := len(ciphervector)

	// check that e and cipher vectors have the same size
	if len(e) != k {
		return libunlynx.CipherText{}, fmt.Errorf("e is not the right size")
	}

	ciphertext := *libunlynx.NewCipherText()
	for i := 0; i < k; i++ {
		aux := libunlynx.NewCipherText()
		aux.MulCipherTextbyScalar(ciphervector[i], e[i])
		ciphertext.Add(ciphertext, *aux)
	}
	return ciphertext, nil
}

// compressListCipherVector applies shuffling compression to a list of ciphervectors
func compressListCipherVector(processResponses []libunlynx.CipherVector, e []kyber.Scalar) ([]kyber.Point, []kyber.Point, error) {
	xC := make([]kyber.Point, len(processResponses))
	xK := make([]kyber.Point, len(processResponses))

	var err error
	mutex := sync.Mutex{}
	wg := libunlynx.StartParallelize(len(processResponses))
	for i, v := range processResponses {
		go func(i int, v libunlynx.CipherVector) {
			defer wg.Done()
			tmp, tmpErr := compressCipherVector(v, e)
			if tmpErr != nil {
				mutex.Lock()
				err = tmpErr
				mutex.Unlock()
				return
			}
			xK[i] = tmp.K
			xC[i] = tmp.C
		}(i, v)
	}
	libunlynx.EndParallelize(wg)

	if err != nil {
		return nil, nil, err
	}

	return xK, xC, nil
}

// compressCipherVectorMultiple applies shuffling compression to 2 ciphervectors corresponding to the input and the output of shuffling
func compressCipherVectorMultiple(inputList, outputList []libunlynx.CipherVector, i int, e []kyber.Scalar, Xhat, XhatBar, Yhat, YhatBar []kyber.Point) error {
	var err error
	mutex := sync.Mutex{}
	wg := libunlynx.StartParallelize(2)
	go func() {
		defer wg.Done()
		tmp, tmpErr := compressCipherVector(inputList[i], e)
		if tmpErr != nil {
			mutex.Lock()
			err = tmpErr
			mutex.Unlock()
			return
		}

		Xhat[i] = tmp.K
		Yhat[i] = tmp.C
	}()
	go func() {
		defer wg.Done()
		tmpBar, tmpErr := compressCipherVector(outputList[i], e)
		if tmpErr != nil {
			mutex.Lock()
			err = tmpErr
			mutex.Unlock()
			return
		}

		XhatBar[i] = tmpBar.K
		YhatBar[i] = tmpBar.C
	}()
	libunlynx.EndParallelize(wg)

	if err != nil {
		return err
	}

	return nil
}

// compressBeta applies shuffling compression to a matrix of scalars
func compressBeta(beta [][]kyber.Scalar, e []kyber.Scalar) []kyber.Scalar {
	k := len(beta)
	NQ := len(beta[0])
	betaCompressed := make([]kyber.Scalar, k)
	wg := libunlynx.StartParallelize(k)
	for i := 0; i < k; i++ {
		betaCompressed[i] = libunlynx.SuiTe.Scalar().Zero()

		go func(i int) {
			defer wg.Done()
			for j := 0; j < NQ; j++ {
				tmp := libunlynx.SuiTe.Scalar().Mul(beta[i][j], e[j])
				betaCompressed[i] = libunlynx.SuiTe.Scalar().Add(betaCompressed[i], tmp)
			}
		}(i)
	}
	libunlynx.EndParallelize(wg)

	return betaCompressed
}

// Marshal
//______________________________________________________________________________________________________________________

// ToBytes transforms PublishedShufflingProof to bytes
func (psp *PublishedShufflingProof) ToBytes() (PublishedShufflingProofBytes, error) {
	pspb := PublishedShufflingProofBytes{}

	// convert OriginalList
	var err error
	mutex := sync.Mutex{}

	wg := libunlynx.StartParallelize(3)
	go func(data []libunlynx.CipherVector) {
		defer wg.Done()
		tmp, tmpLength, tmpErr := libunlynx.ArrayCipherVectorToBytes(data)
		if tmpErr != nil {
			mutex.Lock()
			err = tmpErr
			mutex.Unlock()
			return
		}

		pspb.OriginalList = &tmp
		pspb.OriginalListLength = &tmpLength
	}(psp.OriginalList)

	// convert ShuffledList
	go func(data []libunlynx.CipherVector) {
		defer wg.Done()
		tmp, tmpLength, tmpErr := libunlynx.ArrayCipherVectorToBytes(data)
		if tmpErr != nil {
			mutex.Lock()
			err = tmpErr
			mutex.Unlock()
			return
		}

		pspb.ShuffledList = &tmp
		pspb.ShuffledListLength = &tmpLength
	}(psp.ShuffledList)

	// convert 'the rest'
	go func(G, H kyber.Point, HashProof []byte) {
		defer wg.Done()

		dataG, tmpErr := libunlynx.AbstractPointsToBytes([]kyber.Point{G})
		if tmpErr != nil {
			mutex.Lock()
			err = tmpErr
			mutex.Unlock()
			return
		}
		tmpGBytes := dataG
		pspb.G = &tmpGBytes

		dataH, tmpErr := libunlynx.AbstractPointsToBytes([]kyber.Point{H})
		if tmpErr != nil {
			mutex.Lock()
			err = tmpErr
			mutex.Unlock()
			return
		}
		tmpHBytes := dataH
		pspb.H = &tmpHBytes

		pspb.HashProof = psp.HashProof
	}(psp.G, psp.H, psp.HashProof)

	libunlynx.EndParallelize(wg)

	if err != nil {
		return PublishedShufflingProofBytes{}, err
	}

	return pspb, nil
}

// FromBytes transforms bytes back to PublishedShufflingProof
func (psp *PublishedShufflingProof) FromBytes(pspb PublishedShufflingProofBytes) error {
	var err error
	psp.OriginalList, err = libunlynx.FromBytesToArrayCipherVector(*pspb.OriginalList, *pspb.OriginalListLength)
	if err != nil {
		return err
	}
	psp.ShuffledList, err = libunlynx.FromBytesToArrayCipherVector(*pspb.ShuffledList, *pspb.ShuffledListLength)
	if err != nil {
		return err
	}

	g, err := libunlynx.FromBytesToAbstractPoints(*pspb.G)
	if err != nil {
		return err
	}
	psp.G = g[0]

	h, err := libunlynx.FromBytesToAbstractPoints(*pspb.H)
	if err != nil {
		return err
	}
	psp.H = h[0]
	psp.HashProof = pspb.HashProof

	return nil
}
