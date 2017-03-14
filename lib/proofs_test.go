package lib_test

import (
	"testing"

	"github.com/JoaoAndreSa/MedCo/lib"
	"github.com/stretchr/testify/assert"
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/crypto.v0/random"
	"gopkg.in/dedis/onet.v1/network"
)

//create variables
var secKey = network.Suite.Scalar().Pick(random.Stream)
var pubKey = network.Suite.Point().Mul(network.Suite.Point().Base(), secKey)

var secKeyNew = network.Suite.Scalar().Pick(random.Stream)
var pubKeyNew = network.Suite.Point().Mul(network.Suite.Point().Base(), secKeyNew)

var cipherOne = *lib.EncryptInt(pubKey, 10)

var cipherVect = lib.CipherVector{cipherOne, cipherOne}

// TesKeySwitchingProof tests KEY SWITCHING
func TestKeySwitchingProof(t *testing.T) {
	//test key switching proofs at ciphertext level
	cipherOneSwitched, r := lib.NewCipherText().KeySwitching(cipherOne, cipherOne.K, pubKeyNew, secKey)
	cp := lib.SwitchKeyProofCreation(cipherOne, *cipherOneSwitched, r, secKey, cipherOne.K, pubKeyNew)
	assert.True(t, lib.SwitchKeyCheckProof(cp, pubKey, pubKeyNew, cipherOne, *cipherOneSwitched))

	assert.False(t, lib.SwitchKeyCheckProof(cp, pubKey, pubKeyNew, *lib.NewCipherText().Add(cipherOne, cipherOne), *cipherOneSwitched))
	assert.False(t, lib.SwitchKeyCheckProof(cp, pubKey, pubKeyNew, cipherOne, *lib.NewCipherText().Add(cipherOne, cipherOne)))
	assert.False(t, lib.SwitchKeyCheckProof(cp, pubKey, pubKey, cipherOne, *cipherOneSwitched))
	assert.False(t, lib.SwitchKeyCheckProof(cp, pubKeyNew, pubKeyNew, cipherOne, *cipherOneSwitched))

	cp = lib.SwitchKeyProofCreation(cipherOne, *cipherOneSwitched, secKey, secKey, cipherOne.K, pubKeyNew)
	assert.False(t, lib.SwitchKeyCheckProof(cp, pubKey, pubKeyNew, cipherOne, *cipherOneSwitched))

	cp = lib.SwitchKeyProofCreation(cipherOne, *cipherOneSwitched, r, r, cipherOne.K, pubKeyNew)
	assert.False(t, lib.SwitchKeyCheckProof(cp, pubKey, pubKeyNew, cipherOne, *cipherOneSwitched))

	cp = lib.SwitchKeyProofCreation(cipherOne, *cipherOneSwitched, r, secKey, cipherOne.C, pubKeyNew)
	assert.False(t, lib.SwitchKeyCheckProof(cp, pubKey, pubKeyNew, cipherOne, *cipherOneSwitched))

	cp = lib.SwitchKeyProofCreation(cipherOne, *cipherOneSwitched, r, secKey, cipherOne.K, network.Suite.Point().Add(pubKeyNew, pubKeyNew))
	assert.False(t, lib.SwitchKeyCheckProof(cp, pubKey, pubKeyNew, cipherOne, *cipherOneSwitched))

	// test key switching at ciphervector level
	origEphemKeys := []abstract.Point{cipherOne.K, cipherOne.K}
	switchedVect, rs := lib.NewCipherVector(2).KeySwitching(cipherVect, origEphemKeys, pubKeyNew, secKey)

	cps := lib.VectorSwitchKeyProofCreation(cipherVect, *switchedVect, rs, secKey, []abstract.Point{cipherOne.K, cipherOne.K}, pubKeyNew)
	assert.True(t, lib.PublishedSwitchKeyCheckProof(lib.PublishedSwitchKeyProof{Skp: cps, VectBefore: cipherVect, VectAfter: *switchedVect, K: pubKey, Q: pubKeyNew}))

	assert.False(t, lib.PublishedSwitchKeyCheckProof(lib.PublishedSwitchKeyProof{Skp: cps, VectBefore: cipherVect, VectAfter: cipherVect, K: pubKey, Q: pubKeyNew}))
	assert.False(t, lib.PublishedSwitchKeyCheckProof(lib.PublishedSwitchKeyProof{Skp: cps, VectBefore: *switchedVect, VectAfter: *switchedVect, K: pubKey, Q: pubKeyNew}))
	assert.False(t, lib.PublishedSwitchKeyCheckProof(lib.PublishedSwitchKeyProof{Skp: cps, VectBefore: cipherVect, VectAfter: *switchedVect, K: pubKeyNew, Q: pubKeyNew}))
	assert.False(t, lib.PublishedSwitchKeyCheckProof(lib.PublishedSwitchKeyProof{Skp: cps, VectBefore: cipherVect, VectAfter: *switchedVect, K: pubKey, Q: pubKey}))

	cps = lib.VectorSwitchKeyProofCreation(cipherVect, *switchedVect, rs, secKeyNew, []abstract.Point{cipherOne.K, cipherOne.K}, pubKeyNew)
	assert.False(t, lib.PublishedSwitchKeyCheckProof(lib.PublishedSwitchKeyProof{Skp: cps, VectBefore: cipherVect, VectAfter: *switchedVect, K: pubKeyNew, Q: pubKeyNew}))

	cps = lib.VectorSwitchKeyProofCreation(cipherVect, *switchedVect, rs, secKey, []abstract.Point{cipherOne.K, cipherOne.K}, pubKey)
	assert.False(t, lib.PublishedSwitchKeyCheckProof(lib.PublishedSwitchKeyProof{Skp: cps, VectBefore: cipherVect, VectAfter: *switchedVect, K: pubKeyNew, Q: pubKeyNew}))
}

// TestAddRmProof tests ADD/REMOVE SERVER PROTOCOL proofd
func TestAddRmProof(t *testing.T) {
	//test  at ciphertext level
	result := *lib.NewCipherText()
	cipherOne = *lib.EncryptInt(pubKey, 10)
	cipherVect = lib.CipherVector{cipherOne, cipherOne}
	tmp := network.Suite.Point().Mul(cipherOne.K, secKeyNew)
	result.K = cipherOne.K

	//addition
	toAdd := true
	result.C = network.Suite.Point().Add(cipherOne.C, tmp)
	prf := lib.AddRmProofCreation(cipherOne, result, secKeyNew, toAdd)
	assert.True(t, lib.AddRmCheckProof(prf, pubKeyNew, cipherOne, result, toAdd))
	assert.False(t, lib.AddRmCheckProof(prf, pubKey, cipherOne, result, toAdd))
	assert.False(t, lib.AddRmCheckProof(prf, pubKeyNew, result, result, toAdd))
	assert.False(t, lib.AddRmCheckProof(prf, pubKeyNew, cipherOne, cipherOne, toAdd))
	assert.False(t, lib.AddRmCheckProof(prf, pubKeyNew, cipherOne, result, !toAdd))

	//substraction
	toAdd = false
	result = *lib.NewCipherText()
	cipherOne = *lib.EncryptInt(pubKey, 10)
	tmp = network.Suite.Point().Mul(cipherOne.K, secKeyNew)
	result.K = cipherOne.K
	result.C = network.Suite.Point().Sub(cipherOne.C, tmp)
	prf = lib.AddRmProofCreation(cipherOne, result, secKeyNew, toAdd)
	assert.True(t, lib.AddRmCheckProof(prf, pubKeyNew, cipherOne, result, toAdd))
	assert.False(t, lib.AddRmCheckProof(prf, pubKey, cipherOne, result, toAdd))
	assert.False(t, lib.AddRmCheckProof(prf, pubKeyNew, result, result, toAdd))
	assert.False(t, lib.AddRmCheckProof(prf, pubKeyNew, cipherOne, cipherOne, toAdd))
	assert.False(t, lib.AddRmCheckProof(prf, pubKeyNew, cipherOne, result, !toAdd))

	// test at ciphervector level
	resultAdd := make(lib.CipherVector, len(cipherVect))
	resultSub := make(lib.CipherVector, len(cipherVect))
	for j, w := range cipherVect {
		tmp := network.Suite.Point().Mul(w.K, secKeyNew)
		resultAdd[j].K = w.K
		resultSub[j].K = w.K

		resultAdd[j].C = network.Suite.Point().Add(w.C, tmp)
		resultSub[j].C = network.Suite.Point().Sub(w.C, tmp)
	}
	prfVectAdd := lib.VectorAddRmProofCreation(cipherVect, resultAdd, secKeyNew, true)
	prfVectAddPub := lib.PublishedAddRmProof{Arp: prfVectAdd, VectBefore: cipherVect, VectAfter: resultAdd, Krm: pubKeyNew, ToAdd: true}
	prfVectSub := lib.VectorAddRmProofCreation(cipherVect, resultSub, secKeyNew, false)
	prfVectSubPub := lib.PublishedAddRmProof{Arp: prfVectSub, VectBefore: cipherVect, VectAfter: resultSub, Krm: pubKeyNew, ToAdd: false}
	assert.True(t, lib.PublishedAddRmCheckProof(prfVectAddPub))
	assert.True(t, lib.PublishedAddRmCheckProof(prfVectSubPub))

	prfVectAddPub = lib.PublishedAddRmProof{Arp: prfVectAdd, VectBefore: resultAdd, VectAfter: resultAdd, Krm: pubKeyNew, ToAdd: true}
	prfVectSubPub = lib.PublishedAddRmProof{Arp: prfVectSub, VectBefore: resultAdd, VectAfter: resultSub, Krm: pubKeyNew, ToAdd: false}
	assert.False(t, lib.PublishedAddRmCheckProof(prfVectAddPub))
	assert.False(t, lib.PublishedAddRmCheckProof(prfVectSubPub))

	prfVectAddPub = lib.PublishedAddRmProof{Arp: prfVectAdd, VectBefore: cipherVect, VectAfter: resultSub, Krm: pubKeyNew, ToAdd: true}
	prfVectSubPub = lib.PublishedAddRmProof{Arp: prfVectSub, VectBefore: cipherVect, VectAfter: resultAdd, Krm: pubKeyNew, ToAdd: false}
	assert.False(t, lib.PublishedAddRmCheckProof(prfVectAddPub))
	assert.False(t, lib.PublishedAddRmCheckProof(prfVectSubPub))

	prfVectAddPub = lib.PublishedAddRmProof{Arp: prfVectAdd, VectBefore: cipherVect, VectAfter: resultAdd, Krm: pubKey, ToAdd: true}
	prfVectSubPub = lib.PublishedAddRmProof{Arp: prfVectSub, VectBefore: cipherVect, VectAfter: resultSub, Krm: pubKey, ToAdd: false}
	assert.False(t, lib.PublishedAddRmCheckProof(prfVectAddPub))
	assert.False(t, lib.PublishedAddRmCheckProof(prfVectSubPub))

	prfVectAddPub = lib.PublishedAddRmProof{Arp: prfVectAdd, VectBefore: cipherVect, VectAfter: resultAdd, Krm: pubKeyNew, ToAdd: false}
	prfVectSubPub = lib.PublishedAddRmProof{Arp: prfVectSub, VectBefore: cipherVect, VectAfter: resultSub, Krm: pubKeyNew, ToAdd: true}
	assert.False(t, lib.PublishedAddRmCheckProof(prfVectAddPub))
	assert.False(t, lib.PublishedAddRmCheckProof(prfVectSubPub))

}

func TestDeterministicTaggingProof(t *testing.T) {
	// test tagging switching at ciphertext level
	cipherOneDetTagged := lib.NewCipherText().DeterministicTagging(&cipherOne, secKey, secKeyNew)
	cp1 := lib.DeterministicTagProofCreation(cipherOne, *cipherOneDetTagged, secKey, secKeyNew)
	assert.True(t, lib.DeterministicTagCheckProof(cp1, pubKey, cipherOne, *cipherOneDetTagged))

	assert.False(t, lib.DeterministicTagCheckProof(cp1, pubKey, *lib.NewCipherText().Add(cipherOne, cipherOne), *cipherOneDetTagged))
	assert.False(t, lib.DeterministicTagCheckProof(cp1, pubKey, cipherOne, *lib.NewCipherText().Add(cipherOne, cipherOne)))
	assert.False(t, lib.DeterministicTagCheckProof(cp1, pubKeyNew, cipherOne, *cipherOneDetTagged))

	cp1 = lib.DeterministicTagProofCreation(cipherOne, *cipherOneDetTagged, secKeyNew, secKeyNew)
	assert.False(t, lib.DeterministicTagCheckProof(cp1, pubKey, cipherOne, *cipherOneDetTagged))

	cp1 = lib.DeterministicTagProofCreation(cipherOne, *cipherOneDetTagged, secKey, secKey)
	assert.False(t, lib.DeterministicTagCheckProof(cp1, pubKey, cipherOne, *cipherOneDetTagged))

	// test tag switching at cipherVector level
	TagSwitchedVect := lib.NewCipherVector(2).DeterministicTagging(&cipherVect, secKey, secKeyNew)

	cps1 := lib.VectorDeterministicTagProofCreation(cipherVect, *TagSwitchedVect, secKeyNew, secKey)
	result, _ := lib.PublishedDeterministicTaggingCheckProof(lib.PublishedDeterministicTaggingProof{Dhp: cps1, VectBefore: cipherVect, VectAfter: *TagSwitchedVect, K: pubKey, SB: nil})
	assert.True(t, result)

	cps1 = lib.VectorDeterministicTagProofCreation(cipherVect, *TagSwitchedVect, secKeyNew, secKey)
	result, _ = lib.PublishedDeterministicTaggingCheckProof(lib.PublishedDeterministicTaggingProof{Dhp: cps1, VectBefore: cipherVect, VectAfter: *TagSwitchedVect, K: pubKey, SB: network.Suite.Point().Mul(network.Suite.Point().Base(), secKeyNew)})
	assert.True(t, result)

	cps1 = lib.VectorDeterministicTagProofCreation(cipherVect, *TagSwitchedVect, secKey, secKey)
	result, _ = lib.PublishedDeterministicTaggingCheckProof(lib.PublishedDeterministicTaggingProof{Dhp: cps1, VectBefore: cipherVect, VectAfter: *TagSwitchedVect, K: pubKey, SB: network.Suite.Point().Mul(network.Suite.Point().Base(), secKeyNew)})
	assert.False(t, result)

	cps1 = lib.VectorDeterministicTagProofCreation(cipherVect, *TagSwitchedVect, secKeyNew, secKeyNew)
	result, _ = lib.PublishedDeterministicTaggingCheckProof(lib.PublishedDeterministicTaggingProof{Dhp: cps1, VectBefore: cipherVect, VectAfter: *TagSwitchedVect, K: pubKey, SB: network.Suite.Point().Mul(network.Suite.Point().Base(), secKeyNew)})
	assert.False(t, result)

	cps1 = lib.VectorDeterministicTagProofCreation(cipherVect, *TagSwitchedVect, secKeyNew, secKey)
	result, _ = lib.PublishedDeterministicTaggingCheckProof(lib.PublishedDeterministicTaggingProof{Dhp: cps1, VectBefore: cipherVect, VectAfter: *TagSwitchedVect, K: pubKeyNew, SB: network.Suite.Point().Mul(network.Suite.Point().Base(), secKeyNew)})
	assert.False(t, result)

	cps1 = lib.VectorDeterministicTagProofCreation(cipherVect, *TagSwitchedVect, secKeyNew, secKey)
	result, _ = lib.PublishedDeterministicTaggingCheckProof(lib.PublishedDeterministicTaggingProof{Dhp: cps1, VectBefore: cipherVect, VectAfter: *TagSwitchedVect, K: pubKey, SB: network.Suite.Point().Mul(network.Suite.Point().Base(), secKey)})
	assert.False(t, result)
}

func TestDeterministicTaggingAdditionProof(t *testing.T) {
	cipherOne = *lib.EncryptInt(pubKey, 10)
	toAdd := network.Suite.Point().Mul(network.Suite.Point().Base(), secKey)
	tmp := network.Suite.Point().Add(cipherOne.C, toAdd)

	prf := lib.DetTagAdditionProofCreation(cipherOne.C, secKey, toAdd, tmp)
	assert.True(t, lib.DetTagAdditionProofVerification(prf))

	prf = lib.DetTagAdditionProofCreation(toAdd, secKey, toAdd, tmp)
	assert.False(t, lib.DetTagAdditionProofVerification(prf))

	prf = lib.DetTagAdditionProofCreation(cipherOne.C, secKeyNew, toAdd, tmp)
	assert.False(t, lib.DetTagAdditionProofVerification(prf))

	prf = lib.DetTagAdditionProofCreation(cipherOne.C, secKey, cipherOne.C, tmp)
	assert.False(t, lib.DetTagAdditionProofVerification(prf))

	prf = lib.DetTagAdditionProofCreation(cipherOne.C, secKey, toAdd, toAdd)
	assert.False(t, lib.DetTagAdditionProofVerification(prf))
}

func TestAggregationProof(t *testing.T) {
	tab1 := []int64{1, 2, 3, 6}
	testCipherVect1 := *lib.EncryptIntVector(pubKey, tab1)

	tab2 := []int64{2, 4, 8, 6}
	testCipherVect2 := *lib.EncryptIntVector(pubKey, tab2)

	det1 := testCipherVect2
	det2 := testCipherVect1
	det3 := testCipherVect2

	det1.TaggingDet(secKey, secKey, pubKey, true)
	deterministicGroupAttributes := make(lib.DeterministCipherVector, len(det1))
	for j, c := range det1 {
		deterministicGroupAttributes[j] = lib.DeterministCipherText{Point: c.C}
	}
	newDetResponse1 := lib.FilteredResponseDet{Fr: lib.FilteredResponse{GroupByEnc: testCipherVect2, AggregatingAttributes: testCipherVect1}, DetTagGroupBy: deterministicGroupAttributes.Key()}

	det2.TaggingDet(secKey, secKey, pubKey, true)

	deterministicGroupAttributes = make(lib.DeterministCipherVector, len(det2))
	for j, c := range det2 {
		deterministicGroupAttributes[j] = lib.DeterministCipherText{Point: c.C}
	}
	newDetResponse2 := lib.FilteredResponseDet{Fr: lib.FilteredResponse{GroupByEnc: testCipherVect1, AggregatingAttributes: testCipherVect1}, DetTagGroupBy: deterministicGroupAttributes.Key()}

	det3.TaggingDet(secKey, secKey, pubKey, true)
	deterministicGroupAttributes = make(lib.DeterministCipherVector, len(det3))
	for j, c := range det3 {
		deterministicGroupAttributes[j] = lib.DeterministCipherText{Point: c.C}
	}
	newDetResponse3 := lib.FilteredResponseDet{Fr: lib.FilteredResponse{GroupByEnc: testCipherVect2, AggregatingAttributes: testCipherVect1}, DetTagGroupBy: deterministicGroupAttributes.Key()}

	detResponses := make([]lib.FilteredResponseDet, 3)
	detResponses[0] = newDetResponse1
	detResponses[1] = newDetResponse2
	detResponses[2] = newDetResponse3

	comparisonMap := make(map[lib.GroupingKey]lib.FilteredResponse)
	for _, v := range detResponses {
		lib.AddInMap(comparisonMap, v.DetTagGroupBy, v.Fr)
	}

	PublishedAggregationProof := lib.AggregationProofCreation(detResponses, comparisonMap)
	assert.True(t, lib.AggregationProofVerification(PublishedAggregationProof))

	detResponses[0] = detResponses[1]
	PublishedAggregationProof = lib.AggregationProofCreation(detResponses, comparisonMap)
	assert.False(t, lib.AggregationProofVerification(PublishedAggregationProof))
}

func TestCollectiveAggregationProof(t *testing.T) {
	tab1 := []int64{1, 2, 3, 6}
	testCipherVect1 := *lib.EncryptIntVector(pubKey, tab1)

	tab2 := []int64{2, 4, 8, 6}
	testCipherVect2 := *lib.EncryptIntVector(pubKey, tab2)

	det1 := testCipherVect2
	det2 := testCipherVect1
	det3 := testCipherVect2

	det1.TaggingDet(secKey, secKey, pubKey, true)
	deterministicGroupAttributes := make(lib.DeterministCipherVector, len(det1))
	for j, c := range det1 {
		deterministicGroupAttributes[j] = lib.DeterministCipherText{Point: c.C}
	}
	newDetResponse1 := lib.FilteredResponseDet{Fr: lib.FilteredResponse{GroupByEnc: testCipherVect2, AggregatingAttributes: testCipherVect1}, DetTagGroupBy: deterministicGroupAttributes.Key()}

	det2.TaggingDet(secKey, secKey, pubKey, true)

	deterministicGroupAttributes = make(lib.DeterministCipherVector, len(det2))
	for j, c := range det2 {
		deterministicGroupAttributes[j] = lib.DeterministCipherText{Point: c.C}
	}
	newDetResponse2 := lib.FilteredResponseDet{Fr: lib.FilteredResponse{GroupByEnc: testCipherVect1, AggregatingAttributes: testCipherVect1}, DetTagGroupBy: deterministicGroupAttributes.Key()}

	det3.TaggingDet(secKey, secKey, pubKey, true)
	deterministicGroupAttributes = make(lib.DeterministCipherVector, len(det3))
	for j, c := range det3 {
		deterministicGroupAttributes[j] = lib.DeterministCipherText{Point: c.C}
	}
	newDetResponse3 := lib.FilteredResponseDet{Fr: lib.FilteredResponse{GroupByEnc: testCipherVect2, AggregatingAttributes: testCipherVect1}, DetTagGroupBy: deterministicGroupAttributes.Key()}

	detResponses := make([]lib.FilteredResponseDet, 3)
	detResponses[0] = newDetResponse1
	detResponses[1] = newDetResponse2
	detResponses[2] = newDetResponse3

	comparisonMap := make(map[lib.GroupingKey]lib.FilteredResponse)
	for _, v := range detResponses {
		lib.AddInMap(comparisonMap, v.DetTagGroupBy, v.Fr)
	}

	resultingMap := make(map[lib.GroupingKey]lib.FilteredResponse)
	for i, v := range comparisonMap {
		lib.AddInMap(resultingMap, i, v)
		lib.AddInMap(resultingMap, i, v)
	}

	PublishedCollectiveAggregationProof := lib.CollectiveAggregationProofCreation(comparisonMap, detResponses, resultingMap)
	assert.True(t, lib.CollectiveAggregationProofVerification(PublishedCollectiveAggregationProof))

	PublishedCollectiveAggregationProof = lib.CollectiveAggregationProofCreation(resultingMap, detResponses, comparisonMap)
	assert.False(t, lib.CollectiveAggregationProofVerification(PublishedCollectiveAggregationProof))
}

func TestShufflingProof(t *testing.T) {
	tab1 := []int64{1, 2, 3, 6}
	testCipherVect1 := *lib.EncryptIntVector(pubKey, tab1)

	tab2 := []int64{2, 4, 8, 6}
	testCipherVect2 := *lib.EncryptIntVector(pubKey, tab2)

	responses := make([]lib.ProcessResponse, 3)
	responses[0] = lib.ProcessResponse{GroupByEnc: testCipherVect2, AggregatingAttributes: testCipherVect2}
	responses[1] = lib.ProcessResponse{GroupByEnc: testCipherVect1, AggregatingAttributes: testCipherVect1}
	responses[2] = lib.ProcessResponse{GroupByEnc: testCipherVect2, AggregatingAttributes: testCipherVect1}

	responsesShuffled, pi, beta := lib.ShuffleSequence(responses, nil, pubKey, nil)
	PublishedShufflingProof := lib.ShufflingProofCreation(responses, responsesShuffled, nil, pubKey, beta, pi)
	assert.True(t, lib.ShufflingProofVerification(PublishedShufflingProof, pubKey))

	PublishedShufflingProof = lib.ShufflingProofCreation(responses, responses, nil, pubKey, beta, pi)
	assert.False(t, lib.ShufflingProofVerification(PublishedShufflingProof, pubKey))
}
