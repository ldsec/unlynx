package libunlynx

import (
	"github.com/dedis/kyber"
	"github.com/dedis/kyber/util/random"
	"github.com/dedis/onet/log"
	"math/big"
	"os"
)

// compressCipherVector (slice of ciphertexts) into one ciphertext
func compressCipherVector(ciphervector CipherVector, e []kyber.Scalar) CipherText {
	k := len(ciphervector)

	// check that e and cipher vectors have the same size
	if len(e) != k {
		panic("e is not the right size!")
	}

	ciphertext := *NewCipherText()
	for i := 0; i < k; i++ {
		aux := NewCipherText()
		aux.MulCipherTextbyScalar(ciphervector[i], e[i])
		ciphertext.Add(ciphertext, *aux)
	}
	return ciphertext
}


// CompressListProcessResponse applies shuffling compression to a list of process responses
func CompressListProcessResponse(processResponses []CipherVector, e []kyber.Scalar) ([]kyber.Point, []kyber.Point) {
	xC := make([]kyber.Point, len(processResponses))
	xK := make([]kyber.Point, len(processResponses))

	wg := StartParallelize(len(processResponses))
	for i, v := range processResponses {
		if PARALLELIZE {
			go func(i int, v CipherVector) {
				tmp := compressCipherVector(v, e)
				xK[i] = tmp.K
				xC[i] = tmp.C
				defer wg.Done()
			}(i, v)
		} else {
			tmp := compressCipherVector(v, e)
			xK[i] = tmp.K
			xC[i] = tmp.C
		}
	}

	EndParallelize(wg)
	return xK, xC
}

// CompressBeta applies shuffling compression to a list of list of scalars (beta)
func CompressBeta(beta [][]kyber.Scalar, e []kyber.Scalar) []kyber.Scalar {
	k := len(beta)
	NQ := len(beta[0])
	betaCompressed := make([]kyber.Scalar, k)
	wg := StartParallelize(k)
	for i := 0; i < k; i++ {
		betaCompressed[i] = SuiTe.Scalar().Zero()
		if PARALLELIZE {
			go func(i int) {
				defer wg.Done()
				for j := 0; j < NQ; j++ {
					tmp := SuiTe.Scalar().Mul(beta[i][j], e[j])
					betaCompressed[i] = SuiTe.Scalar().Add(betaCompressed[i], tmp)
				}
			}(i)
		} else {
			for j := 0; j < NQ; j++ {
				tmp := SuiTe.Scalar().Mul(beta[i][j], e[j])
				betaCompressed[i] = SuiTe.Scalar().Add(betaCompressed[i], tmp)
			}
		}

	}
	EndParallelize(wg)

	return betaCompressed
}

// ShuffleSequence applies shuffling to a list of process responses
func ShuffleSequence(inputList []CipherVector, g, h kyber.Point, precomputed []CipherVectorScalar) ([]CipherVector, []int, [][]kyber.Scalar) {
	maxUint := ^uint(0)
	maxInt := int(maxUint >> 1)

	// number of elgamal pairs
	NQ := len(inputList[0])
	k := len(inputList) // number of clients

	rand := SuiTe.RandomStream()
	// Pick a fresh (or precomputed) ElGamal blinding factor for each pair
	beta := make([][]kyber.Scalar, k)
	precomputedPoints := make([]CipherVector, k)
	for i := 0; i < k; i++ {
		if precomputed == nil {
			beta[i] = RandomScalarSlice(NQ)
		} else {
			randInt := random.Int(big.NewInt(int64(maxInt)), rand)

			indice := int(randInt.Int64() % int64(len(precomputed)))
			beta[i] = precomputed[indice].S[0:NQ] //if beta file is bigger than query line responses
			precomputedPoints[i] = precomputed[indice].CipherV[0:NQ]
		}

	}

	// Pick a random permutation
	pi := RandomPermutation(k)

	outputList := make([]CipherVector, k)

	wg := StartParallelize(k)
	for i := 0; i < k; i++ {
		if PARALLELIZE {
			go func(outputList []CipherVector, i int) {
				defer wg.Done()
				processResponseShuffling(pi, i, inputList, outputList, NQ, beta, precomputedPoints, g, h)
			}(outputList, i)
		} else {
			processResponseShuffling(pi, i, inputList, outputList, NQ, beta, precomputedPoints, g, h)
		}
	}
	EndParallelize(wg)

	return outputList, pi, beta
}

// ProcessResponseShuffling applies shuffling and rerandomization to a list of process responses
func processResponseShuffling(pi []int, i int, inputList, outputList []CipherVector, NQ int, beta [][]kyber.Scalar, precomputedPoints []CipherVector, g, h kyber.Point) {
	index := pi[i]
	outputList[i] = *NewCipherVector(NQ)
	wg := StartParallelize(NQ)
	for j := 0; j < NQ; j++ {
		var b kyber.Scalar
		var cipher CipherText
		if len(precomputedPoints[0]) == 0 {
			b = beta[index][j]
		} else {
			cipher = precomputedPoints[index][j]
		}
		if PARALLELIZE {
			go func(j int) {
				defer wg.Done()
				outputList[i].Rerandomize(inputList[index], b, b, cipher, g, h, j)
			}(j)
		} else {
			outputList[i].Rerandomize(inputList[index], b, b, cipher, g, h, j)
		}

	}
	EndParallelize(wg)
}

// CompressProcessResponseMultiple applies shuffling compression to 2 list of process responses corresponding to input and output of shuffling
func CompressProcessResponseMultiple(inputList, outputList []CipherVector, i int, e []kyber.Scalar, Xhat, XhatBar, Yhat, YhatBar []kyber.Point) {
	tmp := compressCipherVector(inputList[i], e)
	Xhat[i] = tmp.K
	Yhat[i] = tmp.C
	tmpBar := compressCipherVector(outputList[i], e)
	XhatBar[i] = tmpBar.K
	YhatBar[i] = tmpBar.C
}

// PrecomputeForShuffling precomputes data to be used in the shuffling protocol (to make it faster) and saves it in a .gob file
func PrecomputeForShuffling(serverName, gobFile string, surveySecret kyber.Scalar, collectiveKey kyber.Point, lineSize int) []CipherVectorScalar {
	log.Lvl1(serverName, " precomputes for shuffling")
	scalarBytes, _ := surveySecret.MarshalBinary()
	precomputeShuffle := CreatePrecomputedRandomize(SuiTe.Point().Base(), collectiveKey, SuiTe.XOF(scalarBytes), lineSize*2, 10)

	encoded, err := EncodeCipherVectorScalar(precomputeShuffle)

	if err != nil {
		log.Error("Error during marshaling")
	}
	WriteToGobFile(gobFile, encoded)

	return precomputeShuffle
}

// PrecomputationWritingForShuffling reads the precomputation data from  .gob file if it already exists or generates a new one
func PrecomputationWritingForShuffling(appFlag bool, gobFile, serverName string, surveySecret kyber.Scalar, collectiveKey kyber.Point, lineSize int) []CipherVectorScalar {
	log.Lvl1(serverName, " precomputes for shuffling")
	var precomputeShuffle []CipherVectorScalar
	if appFlag {
		if _, err := os.Stat(gobFile); os.IsNotExist(err) {
			precomputeShuffle = PrecomputeForShuffling(serverName, gobFile, surveySecret, collectiveKey, lineSize)
		} else {
			var encoded []CipherVectorScalarBytes
			ReadFromGobFile(gobFile, &encoded)

			precomputeShuffle, err = DecodeCipherVectorScalar(encoded)

			if len(precomputeShuffle[0].CipherV) < lineSize {

			}
			if err != nil {
				log.Error("Error during unmarshaling")
			}
		}
	} else {
		scalarBytes, _ := surveySecret.MarshalBinary()
		precomputeShuffle = CreatePrecomputedRandomize(SuiTe.Point().Base(), collectiveKey, SuiTe.XOF(scalarBytes), lineSize*2, 10)
	}
	return precomputeShuffle
}

// ReadPrecomputedFile reads the precomputation data from a .gob file
func ReadPrecomputedFile(fileName string) []CipherVectorScalar {
	var precomputeShuffle []CipherVectorScalar
	if _, err := os.Stat(fileName); !os.IsNotExist(err) {
		var encoded []CipherVectorScalarBytes
		ReadFromGobFile(fileName, &encoded)

		precomputeShuffle, _ = DecodeCipherVectorScalar(encoded)
	} else {
		precomputeShuffle = nil
	}
	return precomputeShuffle
}
