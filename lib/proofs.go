package libunlynx

import (
	"github.com/dedis/kyber"
	"github.com/dedis/kyber/proof"
	"github.com/dedis/kyber/shuffle"
	"github.com/dedis/onet/log"
	"reflect"
	"sync"
)

// SwitchKeyProof proof for key switching
type SwitchKeyProof struct {
	Proof []byte
	b2    kyber.Point
}

// AddRmProof proof for adding/removing a server operations
type AddRmProof struct {
	Proof []byte
	RB    kyber.Point
}

// DeterministicTaggingProof proof for tag creation operation
type DeterministicTaggingProof struct {
	Proof       []byte
	ciminus11Si kyber.Point
	SB          kyber.Point
}

// PublishedSwitchKeyProof contains all infos about proofs for key switching of a ciphervector
type PublishedSwitchKeyProof struct {
	Skp        []SwitchKeyProof
	VectBefore CipherVector
	VectAfter  CipherVector
	K          kyber.Point
	Q          kyber.Point
}

// PublishedAddRmProof contains all infos about proofs for adding/removing operations on a ciphervector
type PublishedAddRmProof struct {
	Arp        map[string]AddRmProof
	VectBefore map[string]CipherText
	VectAfter  map[string]CipherText
	Krm        kyber.Point
	ToAdd      bool
}

// PublishedDeterministicTaggingProof contains all infos about proofs for deterministic tagging of a ciphervector
type PublishedDeterministicTaggingProof struct {
	Dhp        []DeterministicTaggingProof
	VectBefore CipherVector
	VectAfter  CipherVector
	K          kyber.Point
	SB         kyber.Point
}

// PublishedAggregationProof contains all infos about proofs for aggregation of two filtered responses
type PublishedAggregationProof struct {
	FilteredResponses  []FilteredResponseDet
	AggregationResults map[GroupingKey]FilteredResponse
}

// PublishedCollectiveAggregationProof contains all infos about proofs for coll aggregation of filtered responses
type PublishedCollectiveAggregationProof struct {
	Aggregation1       map[GroupingKey]FilteredResponse
	Aggregation2       []FilteredResponseDet
	AggregationResults map[GroupingKey]FilteredResponse
}

// PublishedShufflingProof contains all infos about proofs for shuffling of a ciphervector
type PublishedShufflingProof struct {
	OriginalList []ProcessResponse
	ShuffledList []ProcessResponse
	G            kyber.Point
	H            kyber.Point
	HashProof    []byte
}

// PublishedDetTagAdditionProof contains all infos about proofs for addition in det, tagging of one element
type PublishedDetTagAdditionProof struct {
	C1    kyber.Point
	C2    kyber.Point
	R     kyber.Point
	Proof []byte
}

// PublishedSimpleAdditionProof contains the two added ciphervectors and the resulting ciphervector
type PublishedSimpleAdditionProof struct {
	C1       CipherVector
	C2       CipherVector
	C1PlusC2 CipherVector
}

// ************************************************** KEY SWITCHING ****************************************************

// createPredicateKeySwitch creates predicate for key switching proof
func createPredicateKeySwitch() (predicate proof.Predicate) {
	// For ZKP
	log1 := proof.Rep("c1", "ri", "B")
	log2 := proof.Rep("K", "k", "B")

	// Two-secret representation: prove c = kiB1 + siB2
	rep := proof.Rep("c2", "k", "b2", "ri", "Q")

	// and-predicate: prove that a = kiB1, b = siB2 and c = a + b
	and := proof.And(log1, log2)
	and = proof.And(and, rep)
	predicate = proof.And(and)

	return
}

// SwitchKeyProofCreation creates proof for key switching on 1 ciphertext
func SwitchKeyProofCreation(cBef, cAft CipherText, newRandomness, k kyber.Scalar, originEphemKey, q kyber.Point) SwitchKeyProof {
	predicate := createPredicateKeySwitch()

	B := SuiTe.Point().Base()
	c1 := SuiTe.Point().Sub(cAft.K, cBef.K)
	c2 := SuiTe.Point().Sub(cAft.C, cBef.C)
	b2 := SuiTe.Point().Neg(originEphemKey)

	K := SuiTe.Point().Mul(k, SuiTe.Point().Base())

	sval := map[string]kyber.Scalar{"k": k, "ri": newRandomness}
	pval := map[string]kyber.Point{"B": B, "K": K, "Q": q, "b2": b2, "c2": c2, "c1": c1}

	prover := predicate.Prover(SuiTe, sval, pval, nil) // computes: commitment, challenge, response
	Proof, err := proof.HashProve(SuiTe, "proofTest", prover)

	if err != nil {
		log.Fatal("---------Prover:", err.Error())
	}

	return SwitchKeyProof{Proof: Proof, b2: b2}

}

// VectorSwitchKeyProofCreation creates proof for key switching on 1 ciphervector
func VectorSwitchKeyProofCreation(vBef, vAft CipherVector, newRandomnesses []kyber.Scalar, k kyber.Scalar, originEphemKey []kyber.Point, q kyber.Point) []SwitchKeyProof {
	result := make([]SwitchKeyProof, len(vBef))
	var wg sync.WaitGroup
	if PARALLELIZE {
		for i := 0; i < len(vBef); i = i + VPARALLELIZE {
			wg.Add(1)
			go func(i int) {
				for j := 0; j < VPARALLELIZE && (j+i < len(vBef)); j++ {
					result[i+j] = SwitchKeyProofCreation(vBef[i+j], vAft[i+j], newRandomnesses[i+j], k, originEphemKey[i+j], q)
				}
				defer wg.Done()
			}(i)

		}
		wg.Wait()
	} else {
		for i, v := range vBef {
			result[i] = SwitchKeyProofCreation(v, vAft[i], newRandomnesses[i], k, originEphemKey[i], q)
		}
	}
	return result
}

// SwitchKeyCheckProof checks one proof of key switching
func SwitchKeyCheckProof(cp SwitchKeyProof, K, Q kyber.Point, cBef, cAft CipherText) bool {
	predicate := createPredicateKeySwitch()
	B := SuiTe.Point().Base()
	c1 := SuiTe.Point().Sub(cAft.K, cBef.K)
	c2 := SuiTe.Point().Sub(cAft.C, cBef.C)

	pval := map[string]kyber.Point{"B": B, "K": K, "Q": Q, "b2": cp.b2, "c2": c2, "c1": c1}
	verifier := predicate.Verifier(SuiTe, pval)
	if err := proof.HashVerify(SuiTe, "proofTest", verifier, cp.Proof); err != nil {
		log.Error("---------Verifier:", err.Error())
		return false
	}

	return true
}

// PublishedSwitchKeyCheckProof checks published proofs of key switching
func PublishedSwitchKeyCheckProof(psp PublishedSwitchKeyProof) bool {
	for i, v := range psp.Skp {
		if !SwitchKeyCheckProof(v, psp.K, psp.Q, psp.VectBefore[i], psp.VectAfter[i]) {
			return false
		}
	}
	return true
}

// ************************************************** ADD/RM PROTOCOL **************************************************

// createPredicateAddRm creates predicate for add/rm server protocol
func createPredicateAddRm() (predicate proof.Predicate) {
	// For ZKP
	log1 := proof.Rep("Krm", "k", "B")

	// Two-secret representation: prove c = kiB1 + siB2
	rep := proof.Rep("c2", "k", "rB")

	// and-predicate: prove that a = kiB1, b = siB2 and c = a + b
	and := proof.And(log1, rep)
	predicate = proof.And(and)

	return
}

// AddRmProofCreation creates proof for add/rm server protocol on 1 ciphertext
func AddRmProofCreation(cBef, cAft CipherText, k kyber.Scalar, toAdd bool) AddRmProof {
	predicate := createPredicateAddRm()

	B := SuiTe.Point().Base()
	c2 := SuiTe.Point()
	if toAdd {
		c2 = SuiTe.Point().Sub(cAft.C, cBef.C)
	} else {
		c2 = SuiTe.Point().Sub(cBef.C, cAft.C)
	}

	rB := cBef.K

	K := SuiTe.Point().Mul(k, SuiTe.Point().Base())

	sval := map[string]kyber.Scalar{"k": k}
	pval := map[string]kyber.Point{"B": B, "Krm": K, "c2": c2, "rB": rB}

	prover := predicate.Prover(SuiTe, sval, pval, nil) // computes: commitment, challenge, response
	Proof, err := proof.HashProve(SuiTe, "proofTest", prover)

	if err != nil {
		log.Fatal("---------Prover:", err.Error())
	}

	return AddRmProof{Proof: Proof, RB: rB}

}

// VectorAddRmProofCreation creates proof for add/rm server protocol on 1 ciphervector
func VectorAddRmProofCreation(vBef, vAft map[string]CipherText, k kyber.Scalar, toAdd bool) map[string]AddRmProof {
	result := make(map[string]AddRmProof, len(vBef))
	var wg sync.WaitGroup
	if PARALLELIZE {
		var mutexBf sync.Mutex
		for i := range vBef {
			wg.Add(1)
			go func(i string) {
				defer wg.Done()

				proofAux := AddRmProofCreation(vBef[i], vAft[i], k, toAdd)

				mutexBf.Lock()
				result[i] = proofAux
				mutexBf.Unlock()
			}(i)

		}
		wg.Wait()
	} else {
		for i, v := range vBef {
			result[i] = AddRmProofCreation(v, vAft[i], k, toAdd)
		}
	}
	return result
}

// AddRmCheckProof checks one rm/add proof
func AddRmCheckProof(cp AddRmProof, K kyber.Point, cBef, cAft CipherText, toAdd bool) bool {
	predicate := createPredicateAddRm()
	B := SuiTe.Point().Base()
	c2 := SuiTe.Point()
	if toAdd {
		c2 = SuiTe.Point().Sub(cAft.C, cBef.C)
	} else {
		c2 = SuiTe.Point().Sub(cBef.C, cAft.C)
	}

	pval := map[string]kyber.Point{"B": B, "Krm": K, "c2": c2, "rB": cBef.K}
	verifier := predicate.Verifier(SuiTe, pval)
	if err := proof.HashVerify(SuiTe, "proofTest", verifier, cp.Proof); err != nil {
		log.Error("---------Verifier:", err.Error())
		return false
	}

	log.LLvl1("Proof verified")

	return true
}

// PublishedAddRmCheckProof checks published add/rm protocol proofs
func PublishedAddRmCheckProof(parp PublishedAddRmProof) bool {
	counter := 0
	for i, v := range parp.Arp {
		if !AddRmCheckProof(v, parp.Krm, parp.VectBefore[i], parp.VectAfter[i], parp.ToAdd) {
			return false
		}
		counter++
	}
	return true
}

// ************************************************** DETERMINISTIC TAGGING ******************************************

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
func DeterministicTagProofCreation(cBef, cAft CipherText, k, s kyber.Scalar) DeterministicTaggingProof {
	predicate := createPredicateDeterministicTag()

	ci1 := cAft.K
	ciminus11 := cBef.K
	ci2 := cAft.C
	ciminus12 := cBef.C
	ciminus11Si := SuiTe.Point().Neg(SuiTe.Point().Mul(s, ciminus11))
	K := SuiTe.Point().Mul(k, SuiTe.Point().Base())
	B := SuiTe.Point().Base()
	SB := SuiTe.Point().Mul(s, B)

	sval := map[string]kyber.Scalar{"k": k, "s": s}
	pval := map[string]kyber.Point{"B": B, "K": K, "ciminus11Si": ciminus11Si, "ciminus12": ciminus12, "ciminus11": ciminus11, "ci2": ci2, "ci1": ci1}

	prover := predicate.Prover(SuiTe, sval, pval, nil) // computes: commitment, challenge, response
	Proof, err := proof.HashProve(SuiTe, "proofTest", prover)
	if err != nil {
		log.Fatal("---------Prover:", err.Error())
	}

	return DeterministicTaggingProof{Proof: Proof, ciminus11Si: ciminus11Si, SB: SB}

}

// VectorDeterministicTagProofCreation creates proof for deterministic tagging protocol on 1 ciphervector
func VectorDeterministicTagProofCreation(vBef, vAft CipherVector, s, k kyber.Scalar) []DeterministicTaggingProof {
	result := make([]DeterministicTaggingProof, len(vBef))
	var wg sync.WaitGroup
	if PARALLELIZE {
		for i := 0; i < len(vBef); i = i + VPARALLELIZE {
			wg.Add(1)
			go func(i int) {
				for j := 0; j < VPARALLELIZE && (j+i < len(vBef)); j++ {
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
func DeterministicTagCheckProof(cp DeterministicTaggingProof, K kyber.Point, cBef, cAft CipherText) bool {
	predicate := createPredicateDeterministicTag()
	B := SuiTe.Point().Base()
	ci1 := cAft.K
	ciminus11 := cBef.K
	ci2 := cAft.C
	ciminus12 := cBef.C

	pval := map[string]kyber.Point{"B": B, "K": K, "ciminus11Si": cp.ciminus11Si, "ciminus12": ciminus12, "ciminus11": ciminus11, "ci2": ci2, "ci1": ci1, "SB": cp.SB}
	verifier := predicate.Verifier(SuiTe, pval)
	if err := proof.HashVerify(SuiTe, "proofTest", verifier, cp.Proof); err != nil {
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

// ************************************************** AGGREGATION ****************************************************

// AggregationProofCreation creates a proof for responses aggregation and grouping
func AggregationProofCreation(responses []FilteredResponseDet, aggregatedResults map[GroupingKey]FilteredResponse) PublishedAggregationProof {
	return PublishedAggregationProof{FilteredResponses: responses, AggregationResults: aggregatedResults}
}

// AggregationProofVerification checks a proof for responses aggregation and grouping
func AggregationProofVerification(pap PublishedAggregationProof) bool {
	comparisonMap := make(map[GroupingKey]FilteredResponse)
	for _, v := range pap.FilteredResponses {
		AddInMap(comparisonMap, v.DetTagGroupBy, v.Fr)
	}
	return reflect.DeepEqual(comparisonMap, pap.AggregationResults)
}

// *****************************************COLLECTIVE AGGREGATION ****************************************************

// CollectiveAggregationProofCreation creates a proof for responses collective aggregation and grouping
func CollectiveAggregationProofCreation(aggregated1 map[GroupingKey]FilteredResponse, aggregated2 []FilteredResponseDet, aggregatedResults map[GroupingKey]FilteredResponse) PublishedCollectiveAggregationProof {
	return PublishedCollectiveAggregationProof{Aggregation1: aggregated1, Aggregation2: aggregated2, AggregationResults: aggregatedResults}
}

// CollectiveAggregationProofVerification checks a proof for responses collective aggregation and grouping
func CollectiveAggregationProofVerification(pcap PublishedCollectiveAggregationProof) bool {
	c1 := make(map[GroupingKey]FilteredResponse)
	for i, v := range pcap.Aggregation1 {
		AddInMap(c1, i, v)
	}
	for _, v := range pcap.Aggregation2 {
		AddInMap(c1, v.DetTagGroupBy, v.Fr)
	}

	//compare maps
	result := true
	if len(c1) != len(pcap.AggregationResults) {
		result = false
	}
	for i, v := range c1 {
		for j, w := range v.AggregatingAttributes {
			if !w.C.Equal(pcap.AggregationResults[i].AggregatingAttributes[j].C) {
				result = false
			}
			if !w.K.Equal(pcap.AggregationResults[i].AggregatingAttributes[j].K) {
				result = false
			}
		}
		for j, w := range v.GroupByEnc {
			if !w.C.Equal(pcap.AggregationResults[i].GroupByEnc[j].C) {
				result = false
			}
			if !w.K.Equal(pcap.AggregationResults[i].GroupByEnc[j].K) {
				result = false
			}
		}

	}
	return result
}

// ************************************************ SHUFFLING **********************************************************

// ShuffleProofCreation creates a proof for one shuffle on a list of process response
func shuffleProofCreation(inputList, outputList []ProcessResponse, beta [][]kyber.Scalar, pi []int, h kyber.Point) []byte {
	e := inputList[0].CipherVectorTag(h)
	k := len(inputList)
	// compress data for each line (each list) into one element
	Xhat := make([]kyber.Point, k)
	Yhat := make([]kyber.Point, k)
	XhatBar := make([]kyber.Point, k)
	YhatBar := make([]kyber.Point, k)

	//var betaCompressed []kyber.Scalar
	wg1 := StartParallelize(k)
	for i := 0; i < k; i++ {
		if PARALLELIZE {
			go func(inputList, outputList []ProcessResponse, i int) {
				defer (*wg1).Done()
				CompressProcessResponseMultiple(inputList, outputList, i, e, Xhat, XhatBar, Yhat, YhatBar)
			}(inputList, outputList, i)
		} else {
			CompressProcessResponseMultiple(inputList, outputList, i, e, Xhat, XhatBar, Yhat, YhatBar)
		}
	}
	EndParallelize(wg1)

	betaCompressed := CompressBeta(beta, e)

	rand := SuiTe.RandomStream()

	// do k-shuffle of ElGamal on the (Xhat,Yhat) and check it
	k = len(Xhat)
	if k != len(Yhat) {
		panic("X,Y vectors have inconsistent lengths")
	}
	ps := shuffle.PairShuffle{}
	ps.Init(SuiTe, k)

	prover := func(ctx proof.ProverContext) error {
		return ps.Prove(pi, nil, h, betaCompressed, Xhat, Yhat, rand, ctx)
	}

	prf, err := proof.HashProve(SuiTe, "PairShuffle", prover)
	if err != nil {
		panic("Shuffle proof failed: " + err.Error())
	}
	return prf
}

// ShufflingProofCreation creates a shuffle proof in its publishable version
func ShufflingProofCreation(originalList, shuffledList []ProcessResponse, g, h kyber.Point, beta [][]kyber.Scalar, pi []int) PublishedShufflingProof {
	prf := shuffleProofCreation(originalList, shuffledList, beta, pi, h)
	return PublishedShufflingProof{originalList, shuffledList, g, h, prf}
}

// checkShuffleProof verifies a shuffling proof
func checkShuffleProof(g, h kyber.Point, Xhat, Yhat, XhatBar, YhatBar []kyber.Point, prf []byte) bool {
	verifier := shuffle.Verifier(SuiTe, g, h, Xhat, Yhat, XhatBar, YhatBar)
	err := proof.HashVerify(SuiTe, "PairShuffle", verifier, prf)

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
	if PARALLELIZE {
		wg := StartParallelize(2)
		go func() {
			x, y = CompressListProcessResponse(psp.OriginalList, e)
			defer (*wg).Done()
		}()
		go func() {
			xbar, ybar = CompressListProcessResponse(psp.ShuffledList, e)
			defer (*wg).Done()
		}()

		EndParallelize(wg)
	} else {
		x, y = CompressListProcessResponse(psp.OriginalList, e)
		xbar, ybar = CompressListProcessResponse(psp.ShuffledList, e)
	}

	return checkShuffleProof(psp.G, psp.H, x, y, xbar, ybar, psp.HashProof)
}

// ************************************************** DETERMINISTIC TAGGING ******************************************

// createPredicateDeterministicTagAddition creates predicate for deterministic tagging addition proof
func createPredicateDeterministicTagAddition() (predicate proof.Predicate) {
	// For ZKP
	log1 := proof.Rep("c2", "s", "B")

	predicate = proof.And(log1)

	return
}

// DetTagAdditionProofCreation creates proof for deterministic tagging addition on 1 kyber point
func DetTagAdditionProofCreation(c1 kyber.Point, s kyber.Scalar, c2 kyber.Point, r kyber.Point) PublishedDetTagAdditionProof {
	predicate := createPredicateDeterministicTagAddition()
	B := SuiTe.Point().Base()
	sval := map[string]kyber.Scalar{"s": s}
	pval := map[string]kyber.Point{"B": B, "c1": c1, "c2": c2, "r": r}

	prover := predicate.Prover(SuiTe, sval, pval, nil) // computes: commitment, challenge, response
	Proof, err := proof.HashProve(SuiTe, "proofTest", prover)
	if err != nil {
		log.Fatal("---------Prover:", err.Error())
	}

	return PublishedDetTagAdditionProof{Proof: Proof, C1: c1, C2: c2, R: r}
}

// DetTagAdditionProofVerification checks a deterministic tag addition proof
func DetTagAdditionProofVerification(psap PublishedDetTagAdditionProof) bool {
	predicate := createPredicateDeterministicTagAddition()
	B := SuiTe.Point().Base()
	pval := map[string]kyber.Point{"B": B, "c1": psap.C1, "c2": psap.C2, "r": psap.R}
	verifier := predicate.Verifier(SuiTe, pval)
	partProof := false
	if err := proof.HashVerify(SuiTe, "proofTest", verifier, psap.Proof); err != nil {
		log.Error("---------Verifier:", err.Error())
		return false
	}

	partProof = true
	//log.LLvl1("Proof verified")

	cv := SuiTe.Point().Add(psap.C1, psap.C2)
	return partProof && reflect.DeepEqual(cv, psap.R)
}
