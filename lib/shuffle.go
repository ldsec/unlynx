package lib

import (
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/crypto.v0/random"
	"gopkg.in/dedis/onet.v1/network"
)

// compressCipherVector (slice of ciphertexts) into one ciphertext
func compressCipherVector(ciphervector CipherVector, e []abstract.Scalar) CipherText {
	k := len(ciphervector)

	// check that e and cipher vectors have the same size
	if len(e) != k {
		panic("e is not the right size!")
	}

	ciphertext := *NewCipherText()
	for i := 0; i < k; i++ {
		tmp := NewCipherText().MulCipherTextbyScalar(ciphervector[i], e[i])
		ciphertext.Add(ciphertext, *tmp)
	}
	return ciphertext
}

// CompressClientResponse applies shuffling compression to a client response
func CompressClientResponse(clientResponse ClientResponse, e []abstract.Scalar) CipherText {
	m := len(clientResponse.ProbaGroupingAttributesEnc)
	n := len(clientResponse.AggregatingAttributes)

	// check size of e
	if len(e) != m + n {
		//+o
		panic("e is not the same size as the list")
	}

	sum := *NewCipherText()
	var sum1, sum2 CipherText
	if PARALLELIZE {
		wg := StartParallelize(2)
		go func() {
			sum1 = compressCipherVector(clientResponse.ProbaGroupingAttributesEnc, e[0:m])
			defer wg.Done()
		}()
		go func() {
			sum2 = compressCipherVector(clientResponse.AggregatingAttributes, e[m:m + n])
			defer wg.Done()
		}()
		EndParallelize(wg)
	} else {
		sum1 = compressCipherVector(clientResponse.ProbaGroupingAttributesEnc, e[0:m])
		sum2 = compressCipherVector(clientResponse.AggregatingAttributes, e[m:m + n])
	}

	sum.Add(sum1, sum2)

	return sum
}

// CompressListClientResponse applies shuffling compression to a list of client responses
func CompressListClientResponse(clientResponses []ClientResponse, e []abstract.Scalar) ([]abstract.Point, []abstract.Point) {
	xC := make([]abstract.Point, len(clientResponses))
	xK := make([]abstract.Point, len(clientResponses))

	wg := StartParallelize(len(clientResponses))
	for i, v := range clientResponses {
		if PARALLELIZE {
			go func(i int, v ClientResponse) {
				tmp := CompressClientResponse(v, e)
				xK[i] = tmp.K
				xC[i] = tmp.C
				defer wg.Done()
			}(i, v)
		} else {
			tmp := CompressClientResponse(v, e)
			xK[i] = tmp.K
			xC[i] = tmp.C
		}
	}

	EndParallelize(wg)
	return xK, xC
}

// CompressBeta applies shuffling compression to a list of list of scalars (beta)
func CompressBeta(beta [][]abstract.Scalar, e []abstract.Scalar) []abstract.Scalar {
	k := len(beta)
	NQ := len(beta[0])
	betaCompressed := make([]abstract.Scalar, k)
	wg := StartParallelize(k)
	for i := 0; i < k; i++ {
		betaCompressed[i] = network.Suite.Scalar().Zero()
		if PARALLELIZE {
			go func(i int) {
				defer wg.Done()
				for j := 0; j < NQ; j++ {
					tmp := network.Suite.Scalar().Mul(beta[i][j], e[j])
					betaCompressed[i] = network.Suite.Scalar().Add(betaCompressed[i], tmp)
				}
			}(i)
		} else {
			for j := 0; j < NQ; j++ {
				tmp := network.Suite.Scalar().Mul(beta[i][j], e[j])
				betaCompressed[i] = network.Suite.Scalar().Add(betaCompressed[i], tmp)
			}
		}

	}
	EndParallelize(wg)

	return betaCompressed
}

// ShuffleSequence applies shuffling to a list of client responses
func ShuffleSequence(inputList []ClientResponse, g, h abstract.Point, precomputed []CipherVectorScalar) ([]ClientResponse, []int, [][]abstract.Scalar) {
	//,  []byte) {
	NQ1 := len(inputList[0].ProbaGroupingAttributesEnc)
	NQ2 := len(inputList[0].AggregatingAttributes)

	// number of elgamal pairs
	NQ := NQ1 + NQ2 //+ NQ3

	k := len(inputList) // number of clients

	rand := network.Suite.Cipher(abstract.RandomKey)
	// Pick a fresh (or precomputed) ElGamal blinding factor for each pair
	beta := make([]([]abstract.Scalar), k)
	precomputedPoints := make([]CipherVector, k)
	for i := 0; i < k; i++ {
		if precomputed == nil {
			beta[i] = RandomScalarSlice(NQ)
		} else {
			indice := int(random.Uint64(rand) % uint64(len(precomputed)))
			beta[i] = precomputed[indice].S[0:NQ] //if beta file is bigger than query line responses
			precomputedPoints[i] = precomputed[indice].CipherV[0:NQ]
		}

	}

	// Pick a random permutation
	pi := RandomPermutation(k)

	outputList := make([]ClientResponse, k)

	wg := StartParallelize(k)
	for i := 0; i < k; i++ {
		if PARALLELIZE {
			go func(outputList []ClientResponse, i int) {
				defer wg.Done()
				clientResponseShuffling(pi, i, inputList, outputList, NQ1, NQ2, NQ, beta, precomputedPoints, g, h)
			}(outputList, i)
		} else {
			clientResponseShuffling(pi, i, inputList, outputList, NQ1, NQ2, NQ, beta, precomputedPoints, g, h)
		}
	}
	EndParallelize(wg)

	return outputList, pi, beta
}

// ClientResponseShuffling applies shuffling and rerandomization to a list of client responses
func clientResponseShuffling(pi []int, i int, inputList, outputList []ClientResponse, NQ1, NQ2, NQ int, beta [][]abstract.Scalar, precomputedPoints []CipherVector, g, h abstract.Point) {
	index := pi[i]
	outputList[i].ProbaGroupingAttributesEnc = *NewCipherVector(NQ1)
	outputList[i].AggregatingAttributes = *NewCipherVector(NQ2)
	wg := StartParallelize(NQ)
	for j := 0; j < NQ; j++ {
		var b abstract.Scalar
		var cipher CipherText
		if len(precomputedPoints[0]) == 0 {
			b = beta[index][j]
		} else {
			cipher = precomputedPoints[index][j]
		}
		if PARALLELIZE {
			go func(j int) {
				defer wg.Done()
				if j < NQ1 {
					outputList[i].ProbaGroupingAttributesEnc.Rerandomize(inputList[index].ProbaGroupingAttributesEnc, b, b, cipher, g, h, j)
				} else if j < NQ1 + NQ2 {
					outputList[i].AggregatingAttributes.Rerandomize(inputList[index].AggregatingAttributes, b, b, cipher, g, h, j - NQ1)
				}
			}(j)
		} else {
			if j < NQ1 {
				outputList[i].ProbaGroupingAttributesEnc.Rerandomize(inputList[index].ProbaGroupingAttributesEnc, b, b, cipher, g, h, j)
			} else if j < NQ1 + NQ2 {
				outputList[i].AggregatingAttributes.Rerandomize(inputList[index].AggregatingAttributes, b, b, cipher, g, h, j - NQ1)
			}
		}

	}
	EndParallelize(wg)
}

// CompressClientResponseMultiple applies shuffling compression to 2 list of client responses corresponding to input and output of shuffling
func CompressClientResponseMultiple(inputList, outputList []ClientResponse, i int, e []abstract.Scalar, Xhat, XhatBar, Yhat, YhatBar []abstract.Point) {
	tmp := CompressClientResponse(inputList[i], e)
	Xhat[i] = tmp.K
	Yhat[i] = tmp.C
	tmpBar := CompressClientResponse(outputList[i], e)
	XhatBar[i] = tmpBar.K
	YhatBar[i] = tmpBar.C
}
