package libunlynxshuffle

import (
	"github.com/lca1/unlynx/lib"
	"github.com/lca1/unlynx/lib/tools"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/util/random"
	"go.dedis.ch/onet/v3/log"
	"math/big"
	"os"
)

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

// CompressListProcessResponse applies shuffling compression to a list of process responses
func CompressListProcessResponse(processResponses []libunlynx.CipherVector, e []kyber.Scalar) ([]kyber.Point, []kyber.Point) {
	xC := make([]kyber.Point, len(processResponses))
	xK := make([]kyber.Point, len(processResponses))

	wg := libunlynx.StartParallelize(len(processResponses))
	for i, v := range processResponses {
		if libunlynx.PARALLELIZE {
			go func(i int, v libunlynx.CipherVector) {
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

	libunlynx.EndParallelize(wg)
	return xK, xC
}

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
}

// ShuffleSequence applies shuffling to a list of process responses
func ShuffleSequence(inputList []libunlynx.CipherVector, g, h kyber.Point, precomputed []libunlynx.CipherVectorScalar) ([]libunlynx.CipherVector, []int, [][]kyber.Scalar) {
	maxUint := ^uint(0)
	maxInt := int(maxUint >> 1)

	// number of elgamal pairs
	NQ := len(inputList[0])
	k := len(inputList) // number of clients

	rand := libunlynx.SuiTe.RandomStream()
	// Pick a fresh (or precomputed) ElGamal blinding factor for each pair
	beta := make([][]kyber.Scalar, k)
	precomputedPoints := make([]libunlynx.CipherVector, k)
	for i := 0; i < k; i++ {
		if precomputed == nil {
			beta[i] = libunlynx.RandomScalarSlice(NQ)
		} else {
			randInt := random.Int(big.NewInt(int64(maxInt)), rand)

			indice := int(randInt.Int64() % int64(len(precomputed)))
			beta[i] = precomputed[indice].S[0:NQ] //if beta file is bigger than query line responses
			precomputedPoints[i] = precomputed[indice].CipherV[0:NQ]
		}

	}

	// Pick a random permutation
	pi := libunlynx.RandomPermutation(k)

	outputList := make([]libunlynx.CipherVector, k)

	wg := libunlynx.StartParallelize(k)
	for i := 0; i < k; i++ {
		if libunlynx.PARALLELIZE {
			go func(outputList []libunlynx.CipherVector, i int) {
				defer wg.Done()
				processResponseShuffling(pi, i, inputList, outputList, NQ, beta, precomputedPoints, g, h)
			}(outputList, i)
		} else {
			processResponseShuffling(pi, i, inputList, outputList, NQ, beta, precomputedPoints, g, h)
		}
	}
	libunlynx.EndParallelize(wg)

	return outputList, pi, beta
}

// ProcessResponseShuffling applies shuffling and rerandomization to a list of process responses
func processResponseShuffling(pi []int, i int, inputList, outputList []libunlynx.CipherVector, NQ int, beta [][]kyber.Scalar, precomputedPoints []libunlynx.CipherVector, g, h kyber.Point) {
	index := pi[i]
	outputList[i] = *libunlynx.NewCipherVector(NQ)
	wg := libunlynx.StartParallelize(NQ)
	for j := 0; j < NQ; j++ {
		var b kyber.Scalar
		var cipher libunlynx.CipherText
		if len(precomputedPoints[0]) == 0 {
			b = beta[index][j]
		} else {
			cipher = precomputedPoints[index][j]
		}
		if libunlynx.PARALLELIZE {
			go func(j int) {
				defer wg.Done()
				outputList[i].Rerandomize(inputList[index], b, b, cipher, g, h, j)
			}(j)
		} else {
			outputList[i].Rerandomize(inputList[index], b, b, cipher, g, h, j)
		}

	}
	libunlynx.EndParallelize(wg)
}

// CompressProcessResponseMultiple applies shuffling compression to 2 list of process responses corresponding to input and output of shuffling
func CompressProcessResponseMultiple(inputList, outputList []libunlynx.CipherVector, i int, e []kyber.Scalar, Xhat, XhatBar, Yhat, YhatBar []kyber.Point) {
	tmp := compressCipherVector(inputList[i], e)
	Xhat[i] = tmp.K
	Yhat[i] = tmp.C
	tmpBar := compressCipherVector(outputList[i], e)
	XhatBar[i] = tmpBar.K
	YhatBar[i] = tmpBar.C
}

// PrecomputeForShuffling precomputes data to be used in the shuffling protocol (to make it faster) and saves it in a .gob file
func PrecomputeForShuffling(serverName, gobFile string, surveySecret kyber.Scalar, collectiveKey kyber.Point, lineSize int) []libunlynx.CipherVectorScalar {
	log.Lvl1(serverName, " precomputes for shuffling")
	scalarBytes, _ := surveySecret.MarshalBinary()
	precomputeShuffle := libunlynx.CreatePrecomputedRandomize(libunlynx.SuiTe.Point().Base(), collectiveKey, libunlynx.SuiTe.XOF(scalarBytes), lineSize*2, 10)

	encoded, err := libunlynxtools.EncodeCipherVectorScalar(precomputeShuffle)

	if err != nil {
		log.Error("Error during marshaling")
	}
	libunlynxtools.WriteToGobFile(gobFile, encoded)

	return precomputeShuffle
}

// PrecomputationWritingForShuffling reads the precomputation data from  .gob file if it already exists or generates a new one
func PrecomputationWritingForShuffling(appFlag bool, gobFile, serverName string, surveySecret kyber.Scalar, collectiveKey kyber.Point, lineSize int) []libunlynx.CipherVectorScalar {
	log.Lvl1(serverName, " precomputes for shuffling")
	var precomputeShuffle []libunlynx.CipherVectorScalar
	if appFlag {
		if _, err := os.Stat(gobFile); os.IsNotExist(err) {
			precomputeShuffle = PrecomputeForShuffling(serverName, gobFile, surveySecret, collectiveKey, lineSize)
		} else {
			var encoded []libunlynx.CipherVectorScalarBytes
			libunlynxtools.ReadFromGobFile(gobFile, &encoded)

			precomputeShuffle, err = libunlynxtools.DecodeCipherVectorScalar(encoded)

			if len(precomputeShuffle[0].CipherV) < lineSize {

			}
			if err != nil {
				log.Error("Error during unmarshaling")
			}
		}
	} else {
		scalarBytes, _ := surveySecret.MarshalBinary()
		precomputeShuffle = libunlynx.CreatePrecomputedRandomize(libunlynx.SuiTe.Point().Base(), collectiveKey, libunlynx.SuiTe.XOF(scalarBytes), lineSize*2, 10)
	}
	return precomputeShuffle
}

// ReadPrecomputedFile reads the precomputation data from a .gob file
func ReadPrecomputedFile(fileName string) []libunlynx.CipherVectorScalar {
	var precomputeShuffle []libunlynx.CipherVectorScalar
	if _, err := os.Stat(fileName); !os.IsNotExist(err) {
		var encoded []libunlynx.CipherVectorScalarBytes
		libunlynxtools.ReadFromGobFile(fileName, &encoded)

		precomputeShuffle, _ = libunlynxtools.DecodeCipherVectorScalar(encoded)
	} else {
		precomputeShuffle = nil
	}
	return precomputeShuffle
}
