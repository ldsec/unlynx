package libUnLynx_test

import (
	"github.com/lca1/unlynx/lib"
	"github.com/stretchr/testify/assert"
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/crypto.v0/random"
	"gopkg.in/dedis/onet.v1/network"
	"reflect"
	"testing"
)

var suite = network.Suite

// TestNullCipherText verifies encryption, decryption and behavior of null ciphertexts.
func TestNullCipherText(t *testing.T) {

	secKey, pubKey := libUnLynx.GenKey()

	nullEnc := libUnLynx.EncryptInt(pubKey, 0)
	nullDec := libUnLynx.DecryptInt(secKey, *nullEnc)

	if 0 != nullDec {
		t.Fatal("Decryption of encryption of 0 should be 0, got", nullDec)
	}

	var twoTimesNullEnc = libUnLynx.CipherText{K: suite.Point().Null(), C: suite.Point().Null()}
	twoTimesNullEnc.Add(*nullEnc, *nullEnc)
	twoTimesNullDec := libUnLynx.DecryptInt(secKey, twoTimesNullEnc)

	if 0 != nullDec {
		t.Fatal("Decryption of encryption of 0+0 should be 0, got", twoTimesNullDec)
	}

}

// TestEncryption tests a relatively high number of encryptions.
func TestEncryption(t *testing.T) {

	_, pubKey := libUnLynx.GenKey()

	nbrEncryptions := 2
	for i := 0; i < nbrEncryptions; i++ {
		libUnLynx.EncryptInt(pubKey, 0)
	}
}

// TestDecryptionConcurrent test the multiple encryptions/decryptions at the same time
func TestDecryptionConcurrent(t *testing.T) {
	numThreads := 5

	sec, pubKey := libUnLynx.GenKey()

	libUnLynx.StartParallelize(numThreads)

	for i := 0; i < numThreads; i++ {
		go func() {
			ct := libUnLynx.EncryptInt(pubKey, 0)
			val := libUnLynx.DecryptInt(sec, *ct)
			assert.Equal(t, val, int64(0))
		}()
	}
}

// TestNullCipherText verifies encryption, decryption and behavior of null cipherVectors.
func TestNullCipherVector(t *testing.T) {
	secKey, pubKey := libUnLynx.GenKey()

	nullVectEnc := *libUnLynx.NullCipherVector(10, pubKey)
	nullVectDec := libUnLynx.DecryptIntVector(secKey, &nullVectEnc)

	target := []int64{0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	if !reflect.DeepEqual(nullVectDec, target) {
		t.Fatal("Null vector of dimension 4 should be ", target, "got", nullVectDec)
	}

	twoTimesNullEnc := libUnLynx.NewCipherVector(10)
	twoTimesNullEnc.Add(nullVectEnc, nullVectEnc)
	twoTimesNullDec := libUnLynx.DecryptIntVector(secKey, twoTimesNullEnc)

	if !reflect.DeepEqual(twoTimesNullDec, target) {
		t.Fatal("Null vector + Null vector should be ", target, "got", twoTimesNullDec)
	}
}

// TestHomomorphicOpp tests homomorphic addition.
func TestHomomorphicOpp(t *testing.T) {
	secKey, pubKey := libUnLynx.GenKey()

	cv1 := libUnLynx.EncryptIntVector(pubKey, []int64{0, 1, 2, 3, 100})
	cv2 := libUnLynx.EncryptIntVector(pubKey, []int64{0, 0, 1, 3, 3})
	targetAdd := []int64{0, 1, 3, 6, 103}
	targetSub := []int64{0, 1, 1, 0, 97}
	targetMul := int64(4)

	cv3 := libUnLynx.NewCipherVector(5)
	cv3.Add(*cv1, *cv2)
	cv4 := libUnLynx.NewCipherVector(5)
	cv4.Sub(*cv1, *cv2)
	cv5 := libUnLynx.EncryptInt(pubKey, 2)
	cv5.MulCipherTextbyScalar(*cv5, suite.Scalar().SetInt64(2))

	pAdd := libUnLynx.DecryptIntVector(secKey, cv3)
	pSub := libUnLynx.DecryptIntVector(secKey, cv4)
	pMul := libUnLynx.DecryptInt(secKey, *cv5)

	assert.Equal(t, targetAdd, pAdd)
	assert.Equal(t, targetSub, pSub)
	assert.Equal(t, targetMul, pMul)
}

// TestCryptoTagging tests the deterministic tagging
func TestCryptoTagging(t *testing.T) {
	const N = 5

	groupKey, private, _ := libUnLynx.GenKeys(N)
	_, secretPrivate, _ := libUnLynx.GenKeys(N)

	target := []int64{-8358645081376817152, -8358645081376817152, 2, 3, 2, 5}
	cv := *libUnLynx.EncryptIntVector(groupKey, target)
	for n := 0; n < N; n++ {
		tmp := libUnLynx.NewCipherVector(len(cv))
		tmp.DeterministicTagging(&cv, private[n], secretPrivate[n])

		cv = *tmp

	}
	assert.True(t, cv[0].C.Equal(cv[1].C))
	assert.True(t, cv[2].C.Equal(cv[4].C))
	assert.False(t, cv[0].C.Equal(cv[3].C))
}

// TestCryptoKeySwitching tests key switching.
func TestCryptoKeySwitching(t *testing.T) {
	const N = 5
	groupKey, privates, _ := libUnLynx.GenKeys(N)
	newPrivate, newPublic := libUnLynx.GenKey()

	target := []int64{1, 2, 3, 4, 5}
	cv := libUnLynx.EncryptIntVector(groupKey, target)

	origEphem := make([]abstract.Point, len(*cv))
	kscv := make(libUnLynx.CipherVector, len(*cv))
	for i, c := range *cv {
		origEphem[i] = c.K
		kscv[i].K = suite.Point().Null()
		kscv[i].C = c.C
	}

	for n := 0; n < N; n++ {
		kscv.KeySwitching(kscv, origEphem, newPublic, privates[n])
	}

	res := libUnLynx.DecryptIntVector(newPrivate, &kscv)
	assert.True(t, reflect.DeepEqual(res, target))

}

// TestEqualDeterministCipherText tests equality between deterministic ciphertexts.
func TestEqualDeterministCipherText(t *testing.T) {
	dcv1 := libUnLynx.DeterministCipherVector{libUnLynx.DeterministCipherText{Point: suite.Point().Base()}, libUnLynx.DeterministCipherText{Point: suite.Point().Null()}}
	dcv2 := libUnLynx.DeterministCipherVector{libUnLynx.DeterministCipherText{Point: suite.Point().Base()}, libUnLynx.DeterministCipherText{Point: suite.Point().Null()}}

	assert.True(t, dcv1.Equal(&dcv2))
	assert.True(t, dcv1.Equal(&dcv1))

	dcv1 = libUnLynx.DeterministCipherVector{}
	dcv2 = libUnLynx.DeterministCipherVector{}
	assert.True(t, dcv1.Equal(&dcv2))
	assert.True(t, dcv1.Equal(&dcv1))

	var nilp *libUnLynx.DeterministCipherVector
	pdcv1 := &dcv1
	assert.True(t, pdcv1.Equal(&dcv2))
	assert.False(t, pdcv1.Equal(nilp))

	pdcv1 = nil
	assert.False(t, pdcv1.Equal(&dcv2))
	assert.True(t, pdcv1.Equal(nilp))
}

// TestAbstractPointsConverter tests the abstract points array converter (to bytes)
func TestAbstractPointsConverter(t *testing.T) {
	aps := make([]abstract.Point, 0)

	clientPrivate := network.Suite.Scalar().Pick(random.Stream)

	for i := 0; i < 4; i++ {
		ap := network.Suite.Point().Mul(network.Suite.Point().Base(), clientPrivate)
		aps = append(aps, ap)
	}

	aps_bytes := libUnLynx.AbstractPointsToBytes(aps)
	new_aps := libUnLynx.BytesToAbstractPoints(aps_bytes)

	for i, el := range aps {
		if !reflect.DeepEqual(el.String(), new_aps[i].String()) {
			t.Fatal("Wrong results, expected", el, "but got", new_aps[i])
		}
	}

	t.Log("[AbstractPoints] -> Good results")
}

// TestCiphertextConverter tests the Ciphertext converter (to bytes)
func TestCiphertextConverter(t *testing.T) {
	secKey, pubKey := libUnLynx.GenKey()

	target := int64(2)
	ct := libUnLynx.EncryptInt(pubKey, target)

	ctb := ct.ToBytes()

	new_ct := libUnLynx.CipherText{}
	new_ct.FromBytes(ctb)

	p := libUnLynx.DecryptInt(secKey, new_ct)

	assert.Equal(t, target, p)
}

// TestCipherVectorConverter tests the CipherVector converter (to bytes)
func TestCipherVectorConverter(t *testing.T) {
	secKey, pubKey := libUnLynx.GenKey()

	target := []int64{0, 1, 3, 103, 103}
	cv := libUnLynx.EncryptIntVector(pubKey, target)

	cvb, length := cv.ToBytes()

	new_cv := libUnLynx.CipherVector{}
	new_cv.FromBytes(cvb, length)

	p := libUnLynx.DecryptIntVector(secKey, &new_cv)

	assert.Equal(t, target, p)
}

// TestIntArrayToCipherVector tests the int array to CipherVector converter and IntToPoint + PointToCiphertext
func TestIntArrayToCipherVector(t *testing.T) {
	integers := []int64{1, 2, 3, 4, 5, 6}

	cipherVect := libUnLynx.IntArrayToCipherVector(integers)
	for i, v := range cipherVect {
		B := suite.Point().Base()
		i := suite.Scalar().SetInt64(integers[i])
		M := suite.Point().Mul(B, i)
		N := suite.Point().Null()
		assert.Equal(t, v.C, M)
		assert.Equal(t, v.K, N)
	}
}

func TestB64Serialization(t *testing.T) {
	secKey, pubKey := libUnLynx.GenKey()
	target := []int64{0, 1, 3, 103, 103}
	cv := libUnLynx.EncryptIntVector(pubKey, target)

	for i, ct := range *cv {
		ctSerialized := ct.Serialize()

		// with newciphertext
		ctDeserialized := libUnLynx.NewCipherTextFromBase64(ctSerialized)
		decVal := libUnLynx.DecryptInt(secKey, *ctDeserialized)
		assert.Equal(t, target[i], decVal)

		// with deserialize
		ctDeserializedBis := libUnLynx.NewCipherText()
		ctDeserializedBis.Deserialize(ctSerialized)
		decValBis := libUnLynx.DecryptInt(secKey, *ctDeserializedBis)
		assert.Equal(t, target[i], decValBis)
		assert.Equal(t, decVal, decValBis)
	}
}
