package libunlynx_test

import (
	"github.com/dedis/kyber"
	"github.com/dedis/kyber/util/random"
	"github.com/lca1/unlynx/lib"
	"github.com/stretchr/testify/assert"
	"strconv"
	"testing"
)

//create variables
var secKey = libunlynx.SuiteT.Scalar().Pick(random.New())
var pubKey = libunlynx.SuiteT.Point().Mul(secKey, libunlynx.SuiteT.Point().Base())

var secKeyNew = libunlynx.SuiteT.Scalar().Pick(random.New())
var pubKeyNew = libunlynx.SuiteT.Point().Mul(secKeyNew, libunlynx.SuiteT.Point().Base())

var cipherOne = *libunlynx.EncryptInt(pubKey, 10)

var cipherVect = libunlynx.CipherVector{cipherOne, cipherOne}

// TesKeySwitchingProof tests KEY SWITCHING
func TestKeySwitchingProof(t *testing.T) {
	//test key switching proofs at ciphertext level
	cipherOneSwitched := libunlynx.NewCipherText()
	r := cipherOneSwitched.KeySwitching(cipherOne, cipherOne.K, pubKeyNew, secKey)
	cp := libunlynx.SwitchKeyProofCreation(cipherOne, *cipherOneSwitched, r, secKey, cipherOne.K, pubKeyNew)
	assert.True(t, libunlynx.SwitchKeyCheckProof(cp, pubKey, pubKeyNew, cipherOne, *cipherOneSwitched))

	aux := libunlynx.NewCipherText()
	aux.Add(cipherOne, cipherOne)
	assert.False(t, libunlynx.SwitchKeyCheckProof(cp, pubKey, pubKeyNew, *aux, *cipherOneSwitched))

	aux = libunlynx.NewCipherText()
	aux.Add(cipherOne, cipherOne)
	assert.False(t, libunlynx.SwitchKeyCheckProof(cp, pubKey, pubKeyNew, cipherOne, *aux))
	assert.False(t, libunlynx.SwitchKeyCheckProof(cp, pubKey, pubKey, cipherOne, *cipherOneSwitched))
	assert.False(t, libunlynx.SwitchKeyCheckProof(cp, pubKeyNew, pubKeyNew, cipherOne, *cipherOneSwitched))

	cp = libunlynx.SwitchKeyProofCreation(cipherOne, *cipherOneSwitched, secKey, secKey, cipherOne.K, pubKeyNew)
	assert.False(t, libunlynx.SwitchKeyCheckProof(cp, pubKey, pubKeyNew, cipherOne, *cipherOneSwitched))

	cp = libunlynx.SwitchKeyProofCreation(cipherOne, *cipherOneSwitched, r, r, cipherOne.K, pubKeyNew)
	assert.False(t, libunlynx.SwitchKeyCheckProof(cp, pubKey, pubKeyNew, cipherOne, *cipherOneSwitched))

	cp = libunlynx.SwitchKeyProofCreation(cipherOne, *cipherOneSwitched, r, secKey, cipherOne.C, pubKeyNew)
	assert.False(t, libunlynx.SwitchKeyCheckProof(cp, pubKey, pubKeyNew, cipherOne, *cipherOneSwitched))

	cp = libunlynx.SwitchKeyProofCreation(cipherOne, *cipherOneSwitched, r, secKey, cipherOne.K, libunlynx.SuiteT.Point().Add(pubKeyNew, pubKeyNew))
	assert.False(t, libunlynx.SwitchKeyCheckProof(cp, pubKey, pubKeyNew, cipherOne, *cipherOneSwitched))

	// test key switching at ciphervector level
	origEphemKeys := []kyber.Point{cipherOne.K, cipherOne.K}
	switchedVect := libunlynx.NewCipherVector(2)
	rs := switchedVect.KeySwitching(cipherVect, origEphemKeys, pubKeyNew, secKey)

	cps := libunlynx.VectorSwitchKeyProofCreation(cipherVect, *switchedVect, rs, secKey, []kyber.Point{cipherOne.K, cipherOne.K}, pubKeyNew)
	assert.True(t, libunlynx.PublishedSwitchKeyCheckProof(libunlynx.PublishedSwitchKeyProof{Skp: cps, VectBefore: cipherVect, VectAfter: *switchedVect, K: pubKey, Q: pubKeyNew}))

	assert.False(t, libunlynx.PublishedSwitchKeyCheckProof(libunlynx.PublishedSwitchKeyProof{Skp: cps, VectBefore: cipherVect, VectAfter: cipherVect, K: pubKey, Q: pubKeyNew}))
	assert.False(t, libunlynx.PublishedSwitchKeyCheckProof(libunlynx.PublishedSwitchKeyProof{Skp: cps, VectBefore: *switchedVect, VectAfter: *switchedVect, K: pubKey, Q: pubKeyNew}))
	assert.False(t, libunlynx.PublishedSwitchKeyCheckProof(libunlynx.PublishedSwitchKeyProof{Skp: cps, VectBefore: cipherVect, VectAfter: *switchedVect, K: pubKeyNew, Q: pubKeyNew}))
	assert.False(t, libunlynx.PublishedSwitchKeyCheckProof(libunlynx.PublishedSwitchKeyProof{Skp: cps, VectBefore: cipherVect, VectAfter: *switchedVect, K: pubKey, Q: pubKey}))

	cps = libunlynx.VectorSwitchKeyProofCreation(cipherVect, *switchedVect, rs, secKeyNew, []kyber.Point{cipherOne.K, cipherOne.K}, pubKeyNew)
	assert.False(t, libunlynx.PublishedSwitchKeyCheckProof(libunlynx.PublishedSwitchKeyProof{Skp: cps, VectBefore: cipherVect, VectAfter: *switchedVect, K: pubKeyNew, Q: pubKeyNew}))

	cps = libunlynx.VectorSwitchKeyProofCreation(cipherVect, *switchedVect, rs, secKey, []kyber.Point{cipherOne.K, cipherOne.K}, pubKey)
	assert.False(t, libunlynx.PublishedSwitchKeyCheckProof(libunlynx.PublishedSwitchKeyProof{Skp: cps, VectBefore: cipherVect, VectAfter: *switchedVect, K: pubKeyNew, Q: pubKeyNew}))
}

// TestAddRmProof tests ADD/REMOVE SERVER PROTOCOL proofs
func TestAddRmProof(t *testing.T) {
	//test  at ciphertext level
	result := *libunlynx.NewCipherText()
	cipherOne = *libunlynx.EncryptInt(pubKey, 10)
	cipherMap := make(map[string]libunlynx.CipherText)
	cipherMap["0"] = cipherOne
	cipherMap["1"] = cipherOne

	tmp := libunlynx.SuiteT.Point().Mul(secKeyNew, cipherOne.K)
	result.K = cipherOne.K

	//addition
	result.C = libunlynx.SuiteT.Point().Add(cipherOne.C, tmp)
	prf := libunlynx.AddRmProofCreation(cipherOne, result, secKeyNew, true)
	assert.True(t, libunlynx.AddRmCheckProof(prf, pubKeyNew, cipherOne, result, true))
	assert.False(t, libunlynx.AddRmCheckProof(prf, pubKey, cipherOne, result, true))
	assert.False(t, libunlynx.AddRmCheckProof(prf, pubKeyNew, result, result, true))
	assert.False(t, libunlynx.AddRmCheckProof(prf, pubKeyNew, cipherOne, cipherOne, true))
	assert.False(t, libunlynx.AddRmCheckProof(prf, pubKeyNew, cipherOne, result, false))

	//subtraction
	result = *libunlynx.NewCipherText()
	cipherOne = *libunlynx.EncryptInt(pubKey, 10)
	tmp = libunlynx.SuiteT.Point().Mul(secKeyNew, cipherOne.K)
	result.K = cipherOne.K
	result.C = libunlynx.SuiteT.Point().Sub(cipherOne.C, tmp)
	prf = libunlynx.AddRmProofCreation(cipherOne, result, secKeyNew, false)
	assert.True(t, libunlynx.AddRmCheckProof(prf, pubKeyNew, cipherOne, result, false))
	assert.False(t, libunlynx.AddRmCheckProof(prf, pubKey, cipherOne, result, false))
	assert.False(t, libunlynx.AddRmCheckProof(prf, pubKeyNew, result, result, false))
	assert.False(t, libunlynx.AddRmCheckProof(prf, pubKeyNew, cipherOne, cipherOne, false))
	assert.False(t, libunlynx.AddRmCheckProof(prf, pubKeyNew, cipherOne, result, true))

	resultAdd := make(map[string]libunlynx.CipherText)
	resultSub := make(map[string]libunlynx.CipherText)

	for j := 0; j < len(cipherMap); j++ {
		w := libunlynx.CipherText{K: cipherMap[strconv.Itoa(j)].K, C: cipherMap[strconv.Itoa(j)].C}

		tmp := libunlynx.SuiteT.Point().Mul(secKeyNew, w.K)

		add := libunlynx.CipherText{K: w.K, C: libunlynx.SuiteT.Point().Add(w.C, tmp)}
		sub := libunlynx.CipherText{K: w.K, C: libunlynx.SuiteT.Point().Sub(w.C, tmp)}

		resultAdd[strconv.Itoa(j)] = add
		resultSub[strconv.Itoa(j)] = sub
	}
	prfVectAdd := libunlynx.VectorAddRmProofCreation(cipherMap, resultAdd, secKeyNew, true)
	prfVectAddPub := libunlynx.PublishedAddRmProof{Arp: prfVectAdd, VectBefore: cipherMap, VectAfter: resultAdd, Krm: pubKeyNew, ToAdd: true}
	prfVectSub := libunlynx.VectorAddRmProofCreation(cipherMap, resultSub, secKeyNew, false)
	prfVectSubPub := libunlynx.PublishedAddRmProof{Arp: prfVectSub, VectBefore: cipherMap, VectAfter: resultSub, Krm: pubKeyNew, ToAdd: false}
	assert.True(t, libunlynx.PublishedAddRmCheckProof(prfVectAddPub))
	assert.True(t, libunlynx.PublishedAddRmCheckProof(prfVectSubPub))

	prfVectAddPub = libunlynx.PublishedAddRmProof{Arp: prfVectAdd, VectBefore: resultAdd, VectAfter: resultAdd, Krm: pubKeyNew, ToAdd: true}
	prfVectSubPub = libunlynx.PublishedAddRmProof{Arp: prfVectSub, VectBefore: resultAdd, VectAfter: resultSub, Krm: pubKeyNew, ToAdd: false}
	assert.False(t, libunlynx.PublishedAddRmCheckProof(prfVectAddPub))
	assert.False(t, libunlynx.PublishedAddRmCheckProof(prfVectSubPub))

	prfVectAddPub = libunlynx.PublishedAddRmProof{Arp: prfVectAdd, VectBefore: cipherMap, VectAfter: resultSub, Krm: pubKeyNew, ToAdd: true}
	prfVectSubPub = libunlynx.PublishedAddRmProof{Arp: prfVectSub, VectBefore: cipherMap, VectAfter: resultAdd, Krm: pubKeyNew, ToAdd: false}
	assert.False(t, libunlynx.PublishedAddRmCheckProof(prfVectAddPub))
	assert.False(t, libunlynx.PublishedAddRmCheckProof(prfVectSubPub))

	prfVectAddPub = libunlynx.PublishedAddRmProof{Arp: prfVectAdd, VectBefore: cipherMap, VectAfter: resultAdd, Krm: pubKey, ToAdd: true}
	prfVectSubPub = libunlynx.PublishedAddRmProof{Arp: prfVectSub, VectBefore: cipherMap, VectAfter: resultSub, Krm: pubKey, ToAdd: false}
	assert.False(t, libunlynx.PublishedAddRmCheckProof(prfVectAddPub))
	assert.False(t, libunlynx.PublishedAddRmCheckProof(prfVectSubPub))

	prfVectAddPub = libunlynx.PublishedAddRmProof{Arp: prfVectAdd, VectBefore: cipherMap, VectAfter: resultAdd, Krm: pubKeyNew, ToAdd: false}
	prfVectSubPub = libunlynx.PublishedAddRmProof{Arp: prfVectSub, VectBefore: cipherMap, VectAfter: resultSub, Krm: pubKeyNew, ToAdd: true}
	assert.False(t, libunlynx.PublishedAddRmCheckProof(prfVectAddPub))
	assert.False(t, libunlynx.PublishedAddRmCheckProof(prfVectSubPub))

}

func TestDeterministicTaggingProof(t *testing.T) {
	// test tagging switching at ciphertext level
	cipherOneDetTagged := libunlynx.NewCipherText()
	cipherOneDetTagged.DeterministicTagging(&cipherOne, secKey, secKeyNew)
	cp1 := libunlynx.DeterministicTagProofCreation(cipherOne, *cipherOneDetTagged, secKey, secKeyNew)
	assert.True(t, libunlynx.DeterministicTagCheckProof(cp1, pubKey, cipherOne, *cipherOneDetTagged))

	aux := libunlynx.NewCipherText()
	aux.Add(cipherOne, cipherOne)
	assert.False(t, libunlynx.DeterministicTagCheckProof(cp1, pubKey, *aux, *cipherOneDetTagged))

	aux = libunlynx.NewCipherText()
	aux.Add(cipherOne, cipherOne)
	assert.False(t, libunlynx.DeterministicTagCheckProof(cp1, pubKey, cipherOne, *aux))
	assert.False(t, libunlynx.DeterministicTagCheckProof(cp1, pubKeyNew, cipherOne, *cipherOneDetTagged))

	cp1 = libunlynx.DeterministicTagProofCreation(cipherOne, *cipherOneDetTagged, secKeyNew, secKeyNew)
	assert.False(t, libunlynx.DeterministicTagCheckProof(cp1, pubKey, cipherOne, *cipherOneDetTagged))

	cp1 = libunlynx.DeterministicTagProofCreation(cipherOne, *cipherOneDetTagged, secKey, secKey)
	assert.False(t, libunlynx.DeterministicTagCheckProof(cp1, pubKey, cipherOne, *cipherOneDetTagged))

	// test tag switching at cipherVector level
	TagSwitchedVect := libunlynx.NewCipherVector(2)
	TagSwitchedVect.DeterministicTagging(&cipherVect, secKey, secKeyNew)

	cps1 := libunlynx.VectorDeterministicTagProofCreation(cipherVect, *TagSwitchedVect, secKeyNew, secKey)
	result, _ := libunlynx.PublishedDeterministicTaggingCheckProof(libunlynx.PublishedDeterministicTaggingProof{Dhp: cps1, VectBefore: cipherVect, VectAfter: *TagSwitchedVect, K: pubKey, SB: nil})
	assert.True(t, result)

	cps1 = libunlynx.VectorDeterministicTagProofCreation(cipherVect, *TagSwitchedVect, secKeyNew, secKey)
	result, _ = libunlynx.PublishedDeterministicTaggingCheckProof(libunlynx.PublishedDeterministicTaggingProof{Dhp: cps1, VectBefore: cipherVect, VectAfter: *TagSwitchedVect, K: pubKey, SB: libunlynx.SuiteT.Point().Mul(secKeyNew, libunlynx.SuiteT.Point().Base())})
	assert.True(t, result)

	cps1 = libunlynx.VectorDeterministicTagProofCreation(cipherVect, *TagSwitchedVect, secKey, secKey)
	result, _ = libunlynx.PublishedDeterministicTaggingCheckProof(libunlynx.PublishedDeterministicTaggingProof{Dhp: cps1, VectBefore: cipherVect, VectAfter: *TagSwitchedVect, K: pubKey, SB: libunlynx.SuiteT.Point().Mul(secKeyNew, libunlynx.SuiteT.Point().Base())})
	assert.False(t, result)

	cps1 = libunlynx.VectorDeterministicTagProofCreation(cipherVect, *TagSwitchedVect, secKeyNew, secKeyNew)
	result, _ = libunlynx.PublishedDeterministicTaggingCheckProof(libunlynx.PublishedDeterministicTaggingProof{Dhp: cps1, VectBefore: cipherVect, VectAfter: *TagSwitchedVect, K: pubKey, SB: libunlynx.SuiteT.Point().Mul(secKeyNew, libunlynx.SuiteT.Point().Base())})
	assert.False(t, result)

	cps1 = libunlynx.VectorDeterministicTagProofCreation(cipherVect, *TagSwitchedVect, secKeyNew, secKey)
	result, _ = libunlynx.PublishedDeterministicTaggingCheckProof(libunlynx.PublishedDeterministicTaggingProof{Dhp: cps1, VectBefore: cipherVect, VectAfter: *TagSwitchedVect, K: pubKeyNew, SB: libunlynx.SuiteT.Point().Mul(secKeyNew, libunlynx.SuiteT.Point().Base())})
	assert.False(t, result)

	cps1 = libunlynx.VectorDeterministicTagProofCreation(cipherVect, *TagSwitchedVect, secKeyNew, secKey)
	result, _ = libunlynx.PublishedDeterministicTaggingCheckProof(libunlynx.PublishedDeterministicTaggingProof{Dhp: cps1, VectBefore: cipherVect, VectAfter: *TagSwitchedVect, K: pubKey, SB: libunlynx.SuiteT.Point().Mul(secKey, libunlynx.SuiteT.Point().Base())})
	assert.False(t, result)
}

func TestDeterministicTaggingAdditionProof(t *testing.T) {
	cipherOne = *libunlynx.EncryptInt(pubKey, 10)
	toAdd := libunlynx.SuiteT.Point().Mul(secKey, libunlynx.SuiteT.Point().Base())
	tmp := libunlynx.SuiteT.Point().Add(cipherOne.C, toAdd)

	prf := libunlynx.DetTagAdditionProofCreation(cipherOne.C, secKey, toAdd, tmp)
	assert.True(t, libunlynx.DetTagAdditionProofVerification(prf))

	prf = libunlynx.DetTagAdditionProofCreation(toAdd, secKey, toAdd, tmp)
	assert.False(t, libunlynx.DetTagAdditionProofVerification(prf))

	prf = libunlynx.DetTagAdditionProofCreation(cipherOne.C, secKeyNew, toAdd, tmp)
	assert.False(t, libunlynx.DetTagAdditionProofVerification(prf))

	prf = libunlynx.DetTagAdditionProofCreation(cipherOne.C, secKey, cipherOne.C, tmp)
	assert.False(t, libunlynx.DetTagAdditionProofVerification(prf))

	prf = libunlynx.DetTagAdditionProofCreation(cipherOne.C, secKey, toAdd, toAdd)
	assert.False(t, libunlynx.DetTagAdditionProofVerification(prf))
}

func TestAggregationProof(t *testing.T) {
	tab1 := []int64{1, 2, 3, 6}
	testCipherVect1 := *libunlynx.EncryptIntVector(pubKey, tab1)

	tab2 := []int64{2, 4, 8, 6}
	testCipherVect2 := *libunlynx.EncryptIntVector(pubKey, tab2)

	det1 := testCipherVect2
	det2 := testCipherVect1
	det3 := testCipherVect2

	det1.TaggingDet(secKey, secKey, pubKey, true)
	deterministicGroupAttributes := make(libunlynx.DeterministCipherVector, len(det1))
	for j, c := range det1 {
		deterministicGroupAttributes[j] = libunlynx.DeterministCipherText{Point: c.C}
	}
	newDetResponse1 := libunlynx.FilteredResponseDet{Fr: libunlynx.FilteredResponse{GroupByEnc: testCipherVect2, AggregatingAttributes: testCipherVect1}, DetTagGroupBy: deterministicGroupAttributes.Key()}

	det2.TaggingDet(secKey, secKey, pubKey, true)

	deterministicGroupAttributes = make(libunlynx.DeterministCipherVector, len(det2))
	for j, c := range det2 {
		deterministicGroupAttributes[j] = libunlynx.DeterministCipherText{Point: c.C}
	}
	newDetResponse2 := libunlynx.FilteredResponseDet{Fr: libunlynx.FilteredResponse{GroupByEnc: testCipherVect1, AggregatingAttributes: testCipherVect1}, DetTagGroupBy: deterministicGroupAttributes.Key()}

	det3.TaggingDet(secKey, secKey, pubKey, true)
	deterministicGroupAttributes = make(libunlynx.DeterministCipherVector, len(det3))
	for j, c := range det3 {
		deterministicGroupAttributes[j] = libunlynx.DeterministCipherText{Point: c.C}
	}
	newDetResponse3 := libunlynx.FilteredResponseDet{Fr: libunlynx.FilteredResponse{GroupByEnc: testCipherVect2, AggregatingAttributes: testCipherVect1}, DetTagGroupBy: deterministicGroupAttributes.Key()}

	detResponses := make([]libunlynx.FilteredResponseDet, 3)
	detResponses[0] = newDetResponse1
	detResponses[1] = newDetResponse2
	detResponses[2] = newDetResponse3

	comparisonMap := make(map[libunlynx.GroupingKey]libunlynx.FilteredResponse)
	for _, v := range detResponses {
		libunlynx.AddInMap(comparisonMap, v.DetTagGroupBy, v.Fr)
	}

	PublishedAggregationProof := libunlynx.AggregationProofCreation(detResponses, comparisonMap)
	assert.True(t, libunlynx.AggregationProofVerification(PublishedAggregationProof))

	detResponses[0] = detResponses[1]
	PublishedAggregationProof = libunlynx.AggregationProofCreation(detResponses, comparisonMap)
	assert.False(t, libunlynx.AggregationProofVerification(PublishedAggregationProof))
}

func TestCollectiveAggregationProof(t *testing.T) {
	tab1 := []int64{1, 2, 3, 6}
	testCipherVect1 := *libunlynx.EncryptIntVector(pubKey, tab1)

	tab2 := []int64{2, 4, 8, 6}
	testCipherVect2 := *libunlynx.EncryptIntVector(pubKey, tab2)

	det1 := testCipherVect2
	det2 := testCipherVect1
	det3 := testCipherVect2

	det1.TaggingDet(secKey, secKey, pubKey, true)
	deterministicGroupAttributes := make(libunlynx.DeterministCipherVector, len(det1))
	for j, c := range det1 {
		deterministicGroupAttributes[j] = libunlynx.DeterministCipherText{Point: c.C}
	}
	newDetResponse1 := libunlynx.FilteredResponseDet{Fr: libunlynx.FilteredResponse{GroupByEnc: testCipherVect2, AggregatingAttributes: testCipherVect1}, DetTagGroupBy: deterministicGroupAttributes.Key()}

	det2.TaggingDet(secKey, secKey, pubKey, true)

	deterministicGroupAttributes = make(libunlynx.DeterministCipherVector, len(det2))
	for j, c := range det2 {
		deterministicGroupAttributes[j] = libunlynx.DeterministCipherText{Point: c.C}
	}
	newDetResponse2 := libunlynx.FilteredResponseDet{Fr: libunlynx.FilteredResponse{GroupByEnc: testCipherVect1, AggregatingAttributes: testCipherVect1}, DetTagGroupBy: deterministicGroupAttributes.Key()}

	det3.TaggingDet(secKey, secKey, pubKey, true)
	deterministicGroupAttributes = make(libunlynx.DeterministCipherVector, len(det3))
	for j, c := range det3 {
		deterministicGroupAttributes[j] = libunlynx.DeterministCipherText{Point: c.C}
	}
	newDetResponse3 := libunlynx.FilteredResponseDet{Fr: libunlynx.FilteredResponse{GroupByEnc: testCipherVect2, AggregatingAttributes: testCipherVect1}, DetTagGroupBy: deterministicGroupAttributes.Key()}

	detResponses := make([]libunlynx.FilteredResponseDet, 3)
	detResponses[0] = newDetResponse1
	detResponses[1] = newDetResponse2
	detResponses[2] = newDetResponse3

	comparisonMap := make(map[libunlynx.GroupingKey]libunlynx.FilteredResponse)
	for _, v := range detResponses {
		libunlynx.AddInMap(comparisonMap, v.DetTagGroupBy, v.Fr)
	}

	resultingMap := make(map[libunlynx.GroupingKey]libunlynx.FilteredResponse)
	for i, v := range comparisonMap {
		libunlynx.AddInMap(resultingMap, i, v)
		libunlynx.AddInMap(resultingMap, i, v)
	}

	PublishedCollectiveAggregationProof := libunlynx.CollectiveAggregationProofCreation(comparisonMap, detResponses, resultingMap)
	assert.True(t, libunlynx.CollectiveAggregationProofVerification(PublishedCollectiveAggregationProof))

	PublishedCollectiveAggregationProof = libunlynx.CollectiveAggregationProofCreation(resultingMap, detResponses, comparisonMap)
	assert.False(t, libunlynx.CollectiveAggregationProofVerification(PublishedCollectiveAggregationProof))
}

func TestShufflingProof(t *testing.T) {
	tab1 := []int64{1, 2, 3, 6}
	testCipherVect1 := *libunlynx.EncryptIntVector(pubKey, tab1)

	tab2 := []int64{2, 4, 8, 6}
	testCipherVect2 := *libunlynx.EncryptIntVector(pubKey, tab2)

	responses := make([]libunlynx.ProcessResponse, 3)
	responses[0] = libunlynx.ProcessResponse{GroupByEnc: testCipherVect2, AggregatingAttributes: testCipherVect2}
	responses[1] = libunlynx.ProcessResponse{GroupByEnc: testCipherVect1, AggregatingAttributes: testCipherVect1}
	responses[2] = libunlynx.ProcessResponse{GroupByEnc: testCipherVect2, AggregatingAttributes: testCipherVect1}

	responsesShuffled, pi, beta := libunlynx.ShuffleSequence(responses, nil, pubKey, nil)
	PublishedShufflingProof := libunlynx.ShufflingProofCreation(responses, responsesShuffled, nil, pubKey, beta, pi)
	assert.True(t, libunlynx.ShufflingProofVerification(PublishedShufflingProof, pubKey))

	PublishedShufflingProof = libunlynx.ShufflingProofCreation(responses, responses, nil, pubKey, beta, pi)
	assert.False(t, libunlynx.ShufflingProofVerification(PublishedShufflingProof, pubKey))
}
