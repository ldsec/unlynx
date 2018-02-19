package libUnLynx_test

import (
	"github.com/lca1/unlynx/lib"
	"github.com/stretchr/testify/assert"
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/crypto.v0/random"
	"gopkg.in/dedis/onet.v1/network"
	"strconv"
	"testing"
)

//create variables
var secKey = network.Suite.Scalar().Pick(random.Stream)
var pubKey = network.Suite.Point().Mul(network.Suite.Point().Base(), secKey)

var secKeyNew = network.Suite.Scalar().Pick(random.Stream)
var pubKeyNew = network.Suite.Point().Mul(network.Suite.Point().Base(), secKeyNew)

var cipherOne = *libUnLynx.EncryptInt(pubKey, 10)

var cipherVect = libUnLynx.CipherVector{cipherOne, cipherOne}

// TesKeySwitchingProof tests KEY SWITCHING
func TestKeySwitchingProof(t *testing.T) {
	//test key switching proofs at ciphertext level
	cipherOneSwitched := libUnLynx.NewCipherText()
	r := cipherOneSwitched.KeySwitching(cipherOne, cipherOne.K, pubKeyNew, secKey)
	cp := libUnLynx.SwitchKeyProofCreation(cipherOne, *cipherOneSwitched, r, secKey, cipherOne.K, pubKeyNew)
	assert.True(t, libUnLynx.SwitchKeyCheckProof(cp, pubKey, pubKeyNew, cipherOne, *cipherOneSwitched))

	aux := libUnLynx.NewCipherText()
	aux.Add(cipherOne, cipherOne)
	assert.False(t, libUnLynx.SwitchKeyCheckProof(cp, pubKey, pubKeyNew, *aux, *cipherOneSwitched))

	aux = libUnLynx.NewCipherText()
	aux.Add(cipherOne, cipherOne)
	assert.False(t, libUnLynx.SwitchKeyCheckProof(cp, pubKey, pubKeyNew, cipherOne, *aux))
	assert.False(t, libUnLynx.SwitchKeyCheckProof(cp, pubKey, pubKey, cipherOne, *cipherOneSwitched))
	assert.False(t, libUnLynx.SwitchKeyCheckProof(cp, pubKeyNew, pubKeyNew, cipherOne, *cipherOneSwitched))

	cp = libUnLynx.SwitchKeyProofCreation(cipherOne, *cipherOneSwitched, secKey, secKey, cipherOne.K, pubKeyNew)
	assert.False(t, libUnLynx.SwitchKeyCheckProof(cp, pubKey, pubKeyNew, cipherOne, *cipherOneSwitched))

	cp = libUnLynx.SwitchKeyProofCreation(cipherOne, *cipherOneSwitched, r, r, cipherOne.K, pubKeyNew)
	assert.False(t, libUnLynx.SwitchKeyCheckProof(cp, pubKey, pubKeyNew, cipherOne, *cipherOneSwitched))

	cp = libUnLynx.SwitchKeyProofCreation(cipherOne, *cipherOneSwitched, r, secKey, cipherOne.C, pubKeyNew)
	assert.False(t, libUnLynx.SwitchKeyCheckProof(cp, pubKey, pubKeyNew, cipherOne, *cipherOneSwitched))

	cp = libUnLynx.SwitchKeyProofCreation(cipherOne, *cipherOneSwitched, r, secKey, cipherOne.K, network.Suite.Point().Add(pubKeyNew, pubKeyNew))
	assert.False(t, libUnLynx.SwitchKeyCheckProof(cp, pubKey, pubKeyNew, cipherOne, *cipherOneSwitched))

	// test key switching at ciphervector level
	origEphemKeys := []abstract.Point{cipherOne.K, cipherOne.K}
	switchedVect := libUnLynx.NewCipherVector(2)
	rs := switchedVect.KeySwitching(cipherVect, origEphemKeys, pubKeyNew, secKey)

	cps := libUnLynx.VectorSwitchKeyProofCreation(cipherVect, *switchedVect, rs, secKey, []abstract.Point{cipherOne.K, cipherOne.K}, pubKeyNew)
	assert.True(t, libUnLynx.PublishedSwitchKeyCheckProof(libUnLynx.PublishedSwitchKeyProof{Skp: cps, VectBefore: cipherVect, VectAfter: *switchedVect, K: pubKey, Q: pubKeyNew}))

	assert.False(t, libUnLynx.PublishedSwitchKeyCheckProof(libUnLynx.PublishedSwitchKeyProof{Skp: cps, VectBefore: cipherVect, VectAfter: cipherVect, K: pubKey, Q: pubKeyNew}))
	assert.False(t, libUnLynx.PublishedSwitchKeyCheckProof(libUnLynx.PublishedSwitchKeyProof{Skp: cps, VectBefore: *switchedVect, VectAfter: *switchedVect, K: pubKey, Q: pubKeyNew}))
	assert.False(t, libUnLynx.PublishedSwitchKeyCheckProof(libUnLynx.PublishedSwitchKeyProof{Skp: cps, VectBefore: cipherVect, VectAfter: *switchedVect, K: pubKeyNew, Q: pubKeyNew}))
	assert.False(t, libUnLynx.PublishedSwitchKeyCheckProof(libUnLynx.PublishedSwitchKeyProof{Skp: cps, VectBefore: cipherVect, VectAfter: *switchedVect, K: pubKey, Q: pubKey}))

	cps = libUnLynx.VectorSwitchKeyProofCreation(cipherVect, *switchedVect, rs, secKeyNew, []abstract.Point{cipherOne.K, cipherOne.K}, pubKeyNew)
	assert.False(t, libUnLynx.PublishedSwitchKeyCheckProof(libUnLynx.PublishedSwitchKeyProof{Skp: cps, VectBefore: cipherVect, VectAfter: *switchedVect, K: pubKeyNew, Q: pubKeyNew}))

	cps = libUnLynx.VectorSwitchKeyProofCreation(cipherVect, *switchedVect, rs, secKey, []abstract.Point{cipherOne.K, cipherOne.K}, pubKey)
	assert.False(t, libUnLynx.PublishedSwitchKeyCheckProof(libUnLynx.PublishedSwitchKeyProof{Skp: cps, VectBefore: cipherVect, VectAfter: *switchedVect, K: pubKeyNew, Q: pubKeyNew}))
}

// TestAddRmProof tests ADD/REMOVE SERVER PROTOCOL proofs
func TestAddRmProof(t *testing.T) {
	//test  at ciphertext level
	result := *libUnLynx.NewCipherText()
	cipherOne = *libUnLynx.EncryptInt(pubKey, 10)
	cipherMap := make(map[string]libUnLynx.CipherText)
	cipherMap["0"] = cipherOne
	cipherMap["1"] = cipherOne

	tmp := network.Suite.Point().Mul(cipherOne.K, secKeyNew)
	result.K = cipherOne.K

	//addition
	toAdd := true
	result.C = network.Suite.Point().Add(cipherOne.C, tmp)
	prf := libUnLynx.AddRmProofCreation(cipherOne, result, secKeyNew, toAdd)
	assert.True(t, libUnLynx.AddRmCheckProof(prf, pubKeyNew, cipherOne, result, toAdd))
	assert.False(t, libUnLynx.AddRmCheckProof(prf, pubKey, cipherOne, result, toAdd))
	assert.False(t, libUnLynx.AddRmCheckProof(prf, pubKeyNew, result, result, toAdd))
	assert.False(t, libUnLynx.AddRmCheckProof(prf, pubKeyNew, cipherOne, cipherOne, toAdd))
	assert.False(t, libUnLynx.AddRmCheckProof(prf, pubKeyNew, cipherOne, result, !toAdd))

	//subtraction
	toAdd = false
	result = *libUnLynx.NewCipherText()
	cipherOne = *libUnLynx.EncryptInt(pubKey, 10)
	tmp = network.Suite.Point().Mul(cipherOne.K, secKeyNew)
	result.K = cipherOne.K
	result.C = network.Suite.Point().Sub(cipherOne.C, tmp)
	prf = libUnLynx.AddRmProofCreation(cipherOne, result, secKeyNew, toAdd)
	assert.True(t, libUnLynx.AddRmCheckProof(prf, pubKeyNew, cipherOne, result, toAdd))
	assert.False(t, libUnLynx.AddRmCheckProof(prf, pubKey, cipherOne, result, toAdd))
	assert.False(t, libUnLynx.AddRmCheckProof(prf, pubKeyNew, result, result, toAdd))
	assert.False(t, libUnLynx.AddRmCheckProof(prf, pubKeyNew, cipherOne, cipherOne, toAdd))
	assert.False(t, libUnLynx.AddRmCheckProof(prf, pubKeyNew, cipherOne, result, !toAdd))

	resultAdd := make(map[string]libUnLynx.CipherText)
	resultSub := make(map[string]libUnLynx.CipherText)

	for j := 0; j < len(cipherMap); j++ {
		w := libUnLynx.CipherText{K: cipherMap[strconv.Itoa(j)].K, C: cipherMap[strconv.Itoa(j)].C}

		tmp := network.Suite.Point().Mul(w.K, secKeyNew)

		add := libUnLynx.CipherText{K: w.K, C: network.Suite.Point().Add(w.C, tmp)}
		sub := libUnLynx.CipherText{K: w.K, C: network.Suite.Point().Sub(w.C, tmp)}

		resultAdd[strconv.Itoa(j)] = add
		resultSub[strconv.Itoa(j)] = sub
	}
	prfVectAdd := libUnLynx.VectorAddRmProofCreation(cipherMap, resultAdd, secKeyNew, true)
	prfVectAddPub := libUnLynx.PublishedAddRmProof{Arp: prfVectAdd, VectBefore: cipherMap, VectAfter: resultAdd, Krm: pubKeyNew, ToAdd: true}
	prfVectSub := libUnLynx.VectorAddRmProofCreation(cipherMap, resultSub, secKeyNew, false)
	prfVectSubPub := libUnLynx.PublishedAddRmProof{Arp: prfVectSub, VectBefore: cipherMap, VectAfter: resultSub, Krm: pubKeyNew, ToAdd: false}
	assert.True(t, libUnLynx.PublishedAddRmCheckProof(prfVectAddPub))
	assert.True(t, libUnLynx.PublishedAddRmCheckProof(prfVectSubPub))

	prfVectAddPub = libUnLynx.PublishedAddRmProof{Arp: prfVectAdd, VectBefore: resultAdd, VectAfter: resultAdd, Krm: pubKeyNew, ToAdd: true}
	prfVectSubPub = libUnLynx.PublishedAddRmProof{Arp: prfVectSub, VectBefore: resultAdd, VectAfter: resultSub, Krm: pubKeyNew, ToAdd: false}
	assert.False(t, libUnLynx.PublishedAddRmCheckProof(prfVectAddPub))
	assert.False(t, libUnLynx.PublishedAddRmCheckProof(prfVectSubPub))

	prfVectAddPub = libUnLynx.PublishedAddRmProof{Arp: prfVectAdd, VectBefore: cipherMap, VectAfter: resultSub, Krm: pubKeyNew, ToAdd: true}
	prfVectSubPub = libUnLynx.PublishedAddRmProof{Arp: prfVectSub, VectBefore: cipherMap, VectAfter: resultAdd, Krm: pubKeyNew, ToAdd: false}
	assert.False(t, libUnLynx.PublishedAddRmCheckProof(prfVectAddPub))
	assert.False(t, libUnLynx.PublishedAddRmCheckProof(prfVectSubPub))

	prfVectAddPub = libUnLynx.PublishedAddRmProof{Arp: prfVectAdd, VectBefore: cipherMap, VectAfter: resultAdd, Krm: pubKey, ToAdd: true}
	prfVectSubPub = libUnLynx.PublishedAddRmProof{Arp: prfVectSub, VectBefore: cipherMap, VectAfter: resultSub, Krm: pubKey, ToAdd: false}
	assert.False(t, libUnLynx.PublishedAddRmCheckProof(prfVectAddPub))
	assert.False(t, libUnLynx.PublishedAddRmCheckProof(prfVectSubPub))

	prfVectAddPub = libUnLynx.PublishedAddRmProof{Arp: prfVectAdd, VectBefore: cipherMap, VectAfter: resultAdd, Krm: pubKeyNew, ToAdd: false}
	prfVectSubPub = libUnLynx.PublishedAddRmProof{Arp: prfVectSub, VectBefore: cipherMap, VectAfter: resultSub, Krm: pubKeyNew, ToAdd: true}
	assert.False(t, libUnLynx.PublishedAddRmCheckProof(prfVectAddPub))
	assert.False(t, libUnLynx.PublishedAddRmCheckProof(prfVectSubPub))

}

func TestDeterministicTaggingProof(t *testing.T) {
	// test tagging switching at ciphertext level
	cipherOneDetTagged := libUnLynx.NewCipherText()
	cipherOneDetTagged.DeterministicTagging(&cipherOne, secKey, secKeyNew)
	cp1 := libUnLynx.DeterministicTagProofCreation(cipherOne, *cipherOneDetTagged, secKey, secKeyNew)
	assert.True(t, libUnLynx.DeterministicTagCheckProof(cp1, pubKey, cipherOne, *cipherOneDetTagged))

	aux := libUnLynx.NewCipherText()
	aux.Add(cipherOne, cipherOne)
	assert.False(t, libUnLynx.DeterministicTagCheckProof(cp1, pubKey, *aux, *cipherOneDetTagged))

	aux = libUnLynx.NewCipherText()
	aux.Add(cipherOne, cipherOne)
	assert.False(t, libUnLynx.DeterministicTagCheckProof(cp1, pubKey, cipherOne, *aux))
	assert.False(t, libUnLynx.DeterministicTagCheckProof(cp1, pubKeyNew, cipherOne, *cipherOneDetTagged))

	cp1 = libUnLynx.DeterministicTagProofCreation(cipherOne, *cipherOneDetTagged, secKeyNew, secKeyNew)
	assert.False(t, libUnLynx.DeterministicTagCheckProof(cp1, pubKey, cipherOne, *cipherOneDetTagged))

	cp1 = libUnLynx.DeterministicTagProofCreation(cipherOne, *cipherOneDetTagged, secKey, secKey)
	assert.False(t, libUnLynx.DeterministicTagCheckProof(cp1, pubKey, cipherOne, *cipherOneDetTagged))

	// test tag switching at cipherVector level
	TagSwitchedVect := libUnLynx.NewCipherVector(2)
	TagSwitchedVect.DeterministicTagging(&cipherVect, secKey, secKeyNew)

	cps1 := libUnLynx.VectorDeterministicTagProofCreation(cipherVect, *TagSwitchedVect, secKeyNew, secKey)
	result, _ := libUnLynx.PublishedDeterministicTaggingCheckProof(libUnLynx.PublishedDeterministicTaggingProof{Dhp: cps1, VectBefore: cipherVect, VectAfter: *TagSwitchedVect, K: pubKey, SB: nil})
	assert.True(t, result)

	cps1 = libUnLynx.VectorDeterministicTagProofCreation(cipherVect, *TagSwitchedVect, secKeyNew, secKey)
	result, _ = libUnLynx.PublishedDeterministicTaggingCheckProof(libUnLynx.PublishedDeterministicTaggingProof{Dhp: cps1, VectBefore: cipherVect, VectAfter: *TagSwitchedVect, K: pubKey, SB: network.Suite.Point().Mul(network.Suite.Point().Base(), secKeyNew)})
	assert.True(t, result)

	cps1 = libUnLynx.VectorDeterministicTagProofCreation(cipherVect, *TagSwitchedVect, secKey, secKey)
	result, _ = libUnLynx.PublishedDeterministicTaggingCheckProof(libUnLynx.PublishedDeterministicTaggingProof{Dhp: cps1, VectBefore: cipherVect, VectAfter: *TagSwitchedVect, K: pubKey, SB: network.Suite.Point().Mul(network.Suite.Point().Base(), secKeyNew)})
	assert.False(t, result)

	cps1 = libUnLynx.VectorDeterministicTagProofCreation(cipherVect, *TagSwitchedVect, secKeyNew, secKeyNew)
	result, _ = libUnLynx.PublishedDeterministicTaggingCheckProof(libUnLynx.PublishedDeterministicTaggingProof{Dhp: cps1, VectBefore: cipherVect, VectAfter: *TagSwitchedVect, K: pubKey, SB: network.Suite.Point().Mul(network.Suite.Point().Base(), secKeyNew)})
	assert.False(t, result)

	cps1 = libUnLynx.VectorDeterministicTagProofCreation(cipherVect, *TagSwitchedVect, secKeyNew, secKey)
	result, _ = libUnLynx.PublishedDeterministicTaggingCheckProof(libUnLynx.PublishedDeterministicTaggingProof{Dhp: cps1, VectBefore: cipherVect, VectAfter: *TagSwitchedVect, K: pubKeyNew, SB: network.Suite.Point().Mul(network.Suite.Point().Base(), secKeyNew)})
	assert.False(t, result)

	cps1 = libUnLynx.VectorDeterministicTagProofCreation(cipherVect, *TagSwitchedVect, secKeyNew, secKey)
	result, _ = libUnLynx.PublishedDeterministicTaggingCheckProof(libUnLynx.PublishedDeterministicTaggingProof{Dhp: cps1, VectBefore: cipherVect, VectAfter: *TagSwitchedVect, K: pubKey, SB: network.Suite.Point().Mul(network.Suite.Point().Base(), secKey)})
	assert.False(t, result)
}

func TestDeterministicTaggingAdditionProof(t *testing.T) {
	cipherOne = *libUnLynx.EncryptInt(pubKey, 10)
	toAdd := network.Suite.Point().Mul(network.Suite.Point().Base(), secKey)
	tmp := network.Suite.Point().Add(cipherOne.C, toAdd)

	prf := libUnLynx.DetTagAdditionProofCreation(cipherOne.C, secKey, toAdd, tmp)
	assert.True(t, libUnLynx.DetTagAdditionProofVerification(prf))

	prf = libUnLynx.DetTagAdditionProofCreation(toAdd, secKey, toAdd, tmp)
	assert.False(t, libUnLynx.DetTagAdditionProofVerification(prf))

	prf = libUnLynx.DetTagAdditionProofCreation(cipherOne.C, secKeyNew, toAdd, tmp)
	assert.False(t, libUnLynx.DetTagAdditionProofVerification(prf))

	prf = libUnLynx.DetTagAdditionProofCreation(cipherOne.C, secKey, cipherOne.C, tmp)
	assert.False(t, libUnLynx.DetTagAdditionProofVerification(prf))

	prf = libUnLynx.DetTagAdditionProofCreation(cipherOne.C, secKey, toAdd, toAdd)
	assert.False(t, libUnLynx.DetTagAdditionProofVerification(prf))
}

func TestAggregationProof(t *testing.T) {
	tab1 := []int64{1, 2, 3, 6}
	testCipherVect1 := *libUnLynx.EncryptIntVector(pubKey, tab1)

	tab2 := []int64{2, 4, 8, 6}
	testCipherVect2 := *libUnLynx.EncryptIntVector(pubKey, tab2)

	det1 := testCipherVect2
	det2 := testCipherVect1
	det3 := testCipherVect2

	det1.TaggingDet(secKey, secKey, pubKey, true)
	deterministicGroupAttributes := make(libUnLynx.DeterministCipherVector, len(det1))
	for j, c := range det1 {
		deterministicGroupAttributes[j] = libUnLynx.DeterministCipherText{Point: c.C}
	}
	newDetResponse1 := libUnLynx.FilteredResponseDet{Fr: libUnLynx.FilteredResponse{GroupByEnc: testCipherVect2, AggregatingAttributes: testCipherVect1}, DetTagGroupBy: deterministicGroupAttributes.Key()}

	det2.TaggingDet(secKey, secKey, pubKey, true)

	deterministicGroupAttributes = make(libUnLynx.DeterministCipherVector, len(det2))
	for j, c := range det2 {
		deterministicGroupAttributes[j] = libUnLynx.DeterministCipherText{Point: c.C}
	}
	newDetResponse2 := libUnLynx.FilteredResponseDet{Fr: libUnLynx.FilteredResponse{GroupByEnc: testCipherVect1, AggregatingAttributes: testCipherVect1}, DetTagGroupBy: deterministicGroupAttributes.Key()}

	det3.TaggingDet(secKey, secKey, pubKey, true)
	deterministicGroupAttributes = make(libUnLynx.DeterministCipherVector, len(det3))
	for j, c := range det3 {
		deterministicGroupAttributes[j] = libUnLynx.DeterministCipherText{Point: c.C}
	}
	newDetResponse3 := libUnLynx.FilteredResponseDet{Fr: libUnLynx.FilteredResponse{GroupByEnc: testCipherVect2, AggregatingAttributes: testCipherVect1}, DetTagGroupBy: deterministicGroupAttributes.Key()}

	detResponses := make([]libUnLynx.FilteredResponseDet, 3)
	detResponses[0] = newDetResponse1
	detResponses[1] = newDetResponse2
	detResponses[2] = newDetResponse3

	comparisonMap := make(map[libUnLynx.GroupingKey]libUnLynx.FilteredResponse)
	for _, v := range detResponses {
		libUnLynx.AddInMap(comparisonMap, v.DetTagGroupBy, v.Fr)
	}

	PublishedAggregationProof := libUnLynx.AggregationProofCreation(detResponses, comparisonMap)
	assert.True(t, libUnLynx.AggregationProofVerification(PublishedAggregationProof))

	detResponses[0] = detResponses[1]
	PublishedAggregationProof = libUnLynx.AggregationProofCreation(detResponses, comparisonMap)
	assert.False(t, libUnLynx.AggregationProofVerification(PublishedAggregationProof))
}

func TestCollectiveAggregationProof(t *testing.T) {
	tab1 := []int64{1, 2, 3, 6}
	testCipherVect1 := *libUnLynx.EncryptIntVector(pubKey, tab1)

	tab2 := []int64{2, 4, 8, 6}
	testCipherVect2 := *libUnLynx.EncryptIntVector(pubKey, tab2)

	det1 := testCipherVect2
	det2 := testCipherVect1
	det3 := testCipherVect2

	det1.TaggingDet(secKey, secKey, pubKey, true)
	deterministicGroupAttributes := make(libUnLynx.DeterministCipherVector, len(det1))
	for j, c := range det1 {
		deterministicGroupAttributes[j] = libUnLynx.DeterministCipherText{Point: c.C}
	}
	newDetResponse1 := libUnLynx.FilteredResponseDet{Fr: libUnLynx.FilteredResponse{GroupByEnc: testCipherVect2, AggregatingAttributes: testCipherVect1}, DetTagGroupBy: deterministicGroupAttributes.Key()}

	det2.TaggingDet(secKey, secKey, pubKey, true)

	deterministicGroupAttributes = make(libUnLynx.DeterministCipherVector, len(det2))
	for j, c := range det2 {
		deterministicGroupAttributes[j] = libUnLynx.DeterministCipherText{Point: c.C}
	}
	newDetResponse2 := libUnLynx.FilteredResponseDet{Fr: libUnLynx.FilteredResponse{GroupByEnc: testCipherVect1, AggregatingAttributes: testCipherVect1}, DetTagGroupBy: deterministicGroupAttributes.Key()}

	det3.TaggingDet(secKey, secKey, pubKey, true)
	deterministicGroupAttributes = make(libUnLynx.DeterministCipherVector, len(det3))
	for j, c := range det3 {
		deterministicGroupAttributes[j] = libUnLynx.DeterministCipherText{Point: c.C}
	}
	newDetResponse3 := libUnLynx.FilteredResponseDet{Fr: libUnLynx.FilteredResponse{GroupByEnc: testCipherVect2, AggregatingAttributes: testCipherVect1}, DetTagGroupBy: deterministicGroupAttributes.Key()}

	detResponses := make([]libUnLynx.FilteredResponseDet, 3)
	detResponses[0] = newDetResponse1
	detResponses[1] = newDetResponse2
	detResponses[2] = newDetResponse3

	comparisonMap := make(map[libUnLynx.GroupingKey]libUnLynx.FilteredResponse)
	for _, v := range detResponses {
		libUnLynx.AddInMap(comparisonMap, v.DetTagGroupBy, v.Fr)
	}

	resultingMap := make(map[libUnLynx.GroupingKey]libUnLynx.FilteredResponse)
	for i, v := range comparisonMap {
		libUnLynx.AddInMap(resultingMap, i, v)
		libUnLynx.AddInMap(resultingMap, i, v)
	}

	PublishedCollectiveAggregationProof := libUnLynx.CollectiveAggregationProofCreation(comparisonMap, detResponses, resultingMap)
	assert.True(t, libUnLynx.CollectiveAggregationProofVerification(PublishedCollectiveAggregationProof))

	PublishedCollectiveAggregationProof = libUnLynx.CollectiveAggregationProofCreation(resultingMap, detResponses, comparisonMap)
	assert.False(t, libUnLynx.CollectiveAggregationProofVerification(PublishedCollectiveAggregationProof))
}

func TestShufflingProof(t *testing.T) {
	tab1 := []int64{1, 2, 3, 6}
	testCipherVect1 := *libUnLynx.EncryptIntVector(pubKey, tab1)

	tab2 := []int64{2, 4, 8, 6}
	testCipherVect2 := *libUnLynx.EncryptIntVector(pubKey, tab2)

	responses := make([]libUnLynx.ProcessResponse, 3)
	responses[0] = libUnLynx.ProcessResponse{GroupByEnc: testCipherVect2, AggregatingAttributes: testCipherVect2}
	responses[1] = libUnLynx.ProcessResponse{GroupByEnc: testCipherVect1, AggregatingAttributes: testCipherVect1}
	responses[2] = libUnLynx.ProcessResponse{GroupByEnc: testCipherVect2, AggregatingAttributes: testCipherVect1}

	responsesShuffled, pi, beta := libUnLynx.ShuffleSequence(responses, nil, pubKey, nil)
	PublishedShufflingProof := libUnLynx.ShufflingProofCreation(responses, responsesShuffled, nil, pubKey, beta, pi)
	assert.True(t, libUnLynx.ShufflingProofVerification(PublishedShufflingProof, pubKey))

	PublishedShufflingProof = libUnLynx.ShufflingProofCreation(responses, responses, nil, pubKey, beta, pi)
	assert.False(t, libUnLynx.ShufflingProofVerification(PublishedShufflingProof, pubKey))
}
