package libunlynx

import (
	"encoding"
	"encoding/base64"
	"fmt"
	"github.com/dedis/kyber"
	"github.com/dedis/kyber/util/random"
	"github.com/dedis/onet/log"
	"github.com/fanliao/go-concurrentMap"
	"math/big"
	"strings"
	"sync"
)

// MaxHomomorphicInt is upper bound for integers used in messages, a failed decryption will return this value.
const MaxHomomorphicInt int64 = 100000

// PointToInt creates a map between EC points and integers.
//var PointToInt = make(map[string]int64, MaxHomomorphicInt)
var PointToInt = concurrent.NewConcurrentMap()
var currentGreatestM kyber.Point
var currentGreatestInt int64
var mutex = sync.Mutex{}

// CipherText is an ElGamal encrypted point.
type CipherText struct {
	K, C kyber.Point
}

// CipherVector is a slice of ElGamal encrypted points.
type CipherVector []CipherText

// DeterministCipherText deterministic encryption of a point.
type DeterministCipherText struct {
	Point kyber.Point
}

// DeterministCipherVector slice of deterministic encrypted points.
type DeterministCipherVector []DeterministCipherText

// Constructors
//______________________________________________________________________________________________________________________

// NewCipherText creates a ciphertext of null elements.
func NewCipherText() *CipherText {
	return &CipherText{K: SuiTe.Point().Null(), C: SuiTe.Point().Null()}
}

// NewCipherTextFromBase64 creates a ciphertext of null elements.
func NewCipherTextFromBase64(b64Encoded string) *CipherText {
	cipherText := &CipherText{K: SuiTe.Point().Null(), C: SuiTe.Point().Null()}
	(*cipherText).Deserialize(b64Encoded)
	return cipherText
}

// NewCipherVector creates a ciphervector of null elements.
func NewCipherVector(length int) *CipherVector {
	cv := make(CipherVector, length)
	for i := 0; i < length; i++ {
		cv[i] = CipherText{SuiTe.Point().Null(), SuiTe.Point().Null()}
	}
	return &cv
}

// NewDeterministicCipherText create determinist cipher text of null element.
func NewDeterministicCipherText() *DeterministCipherText {
	dc := DeterministCipherText{SuiTe.Point().Null()}
	return &dc
}

// NewDeterministicCipherVector creates a vector of determinist ciphertext of null elements.
func NewDeterministicCipherVector(length int) *DeterministCipherVector {
	dcv := make(DeterministCipherVector, length)
	for i := 0; i < length; i++ {
		dcv[i] = DeterministCipherText{SuiTe.Point().Null()}
	}
	return &dcv
}

// Key Pairs (mostly used in tests)
//----------------------------------------------------------------------------------------------------------------------

// GenKey permits to generate a public/private key pairs.
func GenKey() (secKey kyber.Scalar, pubKey kyber.Point) {
	secKey = SuiTe.Scalar().Pick(random.New())
	pubKey = SuiTe.Point().Mul(secKey, SuiTe.Point().Base())
	return
}

// GenKeys permits to generate ElGamal public/private key pairs.
func GenKeys(n int) (kyber.Point, []kyber.Scalar, []kyber.Point) {
	priv := make([]kyber.Scalar, n)
	pub := make([]kyber.Point, n)
	group := SuiTe.Point().Null()
	for i := 0; i < n; i++ {
		priv[i], pub[i] = GenKey()
		group.Add(group, pub[i])
	}
	return group, priv, pub
}

// Encryption
//______________________________________________________________________________________________________________________

// encryptPoint creates an elliptic curve point from a non-encrypted point and encrypt it using ElGamal encryption.
func encryptPoint(pubkey kyber.Point, M kyber.Point) *CipherText {
	B := SuiTe.Point().Base()
	k := SuiTe.Scalar().Pick(random.New()) // ephemeral private key
	// ElGamal-encrypt the point to produce ciphertext (K,C).
	K := SuiTe.Point().Mul(k, B)      // ephemeral DH public key
	S := SuiTe.Point().Mul(k, pubkey) // ephemeral DH shared secret
	C := S.Add(S, M)                  // message blinded with secret
	return &CipherText{K, C}
}

// IntToPoint maps an integer to a point in the elliptic curve
func IntToPoint(integer int64) kyber.Point {
	B := SuiTe.Point().Base()
	i := SuiTe.Scalar().SetInt64(integer)
	M := SuiTe.Point().Mul(i, B)
	return M
}

// PointToCipherText converts a point into a ciphertext
func PointToCipherText(point kyber.Point) CipherText {
	return CipherText{K: SuiTe.Point().Null(), C: point}
}

// IntToCipherText converts an int into a ciphertext
func IntToCipherText(integer int64) CipherText {
	return PointToCipherText(IntToPoint(integer))
}

// IntArrayToCipherVector converts an array of int to a CipherVector
func IntArrayToCipherVector(integers []int64) CipherVector {
	result := make(CipherVector, len(integers))
	for i, v := range integers {
		result[i] = PointToCipherText(IntToPoint(v))
	}
	return result
}

// EncryptInt encodes i as iB, encrypt it into a CipherText and returns a pointer to it.
func EncryptInt(pubkey kyber.Point, integer int64) *CipherText {
	return encryptPoint(pubkey, IntToPoint(integer))
}

// EncryptScalar encodes i as iB, encrypt it into a CipherText and returns a pointer to it.
func EncryptScalar(pubkey kyber.Point, scalar kyber.Scalar) *CipherText {
	return encryptPoint(pubkey, SuiTe.Point().Mul(scalar, SuiTe.Point().Base()))
}

// EncryptIntVector encrypts a []int into a CipherVector and returns a pointer to it.
func EncryptIntVector(pubkey kyber.Point, intArray []int64) *CipherVector {
	var wg sync.WaitGroup
	cv := make(CipherVector, len(intArray))
	if PARALLELIZE {
		for i := 0; i < len(intArray); i = i + VPARALLELIZE {
			wg.Add(1)
			go func(i int) {
				for j := 0; j < VPARALLELIZE && (j+i < len(intArray)); j++ {
					cv[j+i] = *EncryptInt(pubkey, intArray[j+i])
				}
				defer wg.Done()
			}(i)

		}
		wg.Wait()
	} else {
		for i, n := range intArray {
			cv[i] = *EncryptInt(pubkey, n)
		}
	}

	return &cv
}

// EncryptScalarVector encrypts a []kyber.Scalar into a CipherVector and returns a pointer to it.
func EncryptScalarVector(pubkey kyber.Point, intArray []kyber.Scalar) *CipherVector {
	var wg sync.WaitGroup
	cv := make(CipherVector, len(intArray))
	if PARALLELIZE {
		for i := 0; i < len(intArray); i = i + VPARALLELIZE {
			wg.Add(1)
			go func(i int) {
				for j := 0; j < VPARALLELIZE && (j+i < len(intArray)); j++ {
					cv[j+i] = *EncryptScalar(pubkey, intArray[j+i])
				}
				defer wg.Done()
			}(i)

		}
		wg.Wait()
	} else {
		for i, n := range intArray {
			cv[i] = *EncryptScalar(pubkey, n)
		}
	}

	return &cv
}

// NullCipherVector encrypts an 0-filled slice under the given public key.
func NullCipherVector(length int, pubkey kyber.Point) *CipherVector {
	return EncryptIntVector(pubkey, make([]int64, length))
}

// Decryption
//______________________________________________________________________________________________________________________

// decryptPoint decrypts an elliptic point from an El-Gamal cipher text.
func decryptPoint(prikey kyber.Scalar, c CipherText) kyber.Point {
	S := SuiTe.Point().Mul(prikey, c.K) // regenerate shared secret
	M := SuiTe.Point().Sub(c.C, S)      // use to un-blind the message
	return M
}

// DecryptInt decrypts an integer from an ElGamal cipher text where integer are encoded in the exponent.
func DecryptInt(prikey kyber.Scalar, cipher CipherText) int64 {
	M := decryptPoint(prikey, cipher)
	return discreteLog(M, false)
}

// DecryptIntWithNeg decrypts an integer from an ElGamal cipher text where integer are encoded in the exponent.
func DecryptIntWithNeg(prikey kyber.Scalar, cipher CipherText) int64 {
	M := decryptPoint(prikey, cipher)
	return discreteLog(M, true)
}

// DecryptIntVector decrypts a cipherVector.
func DecryptIntVector(prikey kyber.Scalar, cipherVector *CipherVector) []int64 {
	result := make([]int64, len(*cipherVector))
	for i, c := range *cipherVector {
		result[i] = DecryptInt(prikey, c)
	}
	return result
}

// DecryptIntVectorWithNeg decrypts a cipherVector.
func DecryptIntVectorWithNeg(prikey kyber.Scalar, cipherVector *CipherVector) []int64 {
	result := make([]int64, len(*cipherVector))
	for i, c := range *cipherVector {
		result[i] = DecryptIntWithNeg(prikey, c)
	}
	return result
}

// DecryptCheckZero decrypts an ElGamal cipher text and return 0 if it's a base point
func DecryptCheckZero(prikey kyber.Scalar, cipher CipherText) int64 {
	M := decryptPoint(prikey, cipher)
	result := int64(1)
	if M.Equal(SuiTe.Point().Null()) {
		result = int64(0)
	}
	return result
}

// DecryptCheckZeroVector decrypts a cipherVector with 0 and 1 depending if the decode points are base points.
func DecryptCheckZeroVector(prikey kyber.Scalar, cipherVector *CipherVector) []int64 {
	result := make([]int64, len(*cipherVector))
	for i, c := range *cipherVector {
		result[i] = DecryptCheckZero(prikey, c)
	}
	return result
}

// Brute-Forces the discrete log for integer decoding.
func discreteLog(P kyber.Point, checkNeg bool) int64 {
	B := SuiTe.Point().Base()

	//check if the point is already in the table
	decrypted, ok := PointToInt.Get(P.String())
	if ok == nil && decrypted != nil {
		return decrypted.(int64)
	}

	//otherwise, we complete/create the table while decrypting
	mutex.Lock()

	//initialise
	if currentGreatestInt == 0 {
		currentGreatestM = SuiTe.Point().Null()
	}
	foundPos := false
	foundNeg := false
	guess := currentGreatestM
	guessInt := currentGreatestInt
	guessNeg := SuiTe.Point().Null()
	guessInt_minus := int64(0)

	start := true
	for i := guessInt; i < MaxHomomorphicInt && !foundPos && ! foundNeg; i = i+ 1 {
		// check for 0 first
		if !start {
			guess = SuiTe.Point().Add(guess, B)
		}
		start = false

		guessInt = i
		PointToInt.Put(guess.String(), guessInt)
		if checkNeg {
			guessInt_minus = -guessInt
			guessNeg = SuiTe.Point().Mul(SuiTe.Scalar().SetInt64(guessInt_minus), B)
			PointToInt.Put(guessNeg.String(), guessInt_minus)

			if guessNeg.Equal(P) {
				foundNeg = true
			}
		}
		if !foundNeg && guess.Equal(P){
			foundPos = true
		}
	}
	currentGreatestM = guess
	currentGreatestInt = guessInt
	mutex.Unlock()

	if !foundPos && !foundNeg {
		log.LLvl1("out of bound encryption, bound is ", MaxHomomorphicInt)
		return 0
	} else {
		if foundNeg{
			return guessInt_minus
		} else {
			return guessInt
		}
	}
}

//OLD, TODO remove when sure new one is ok
// Brute-Forces the discrete log for integer decoding.
/*func discreteLog(P kyber.Point, checkNeg bool) int64 {
	B := SuiTe.Point().Base()
	var Bi kyber.Point
	var m int64

	object, ok := PointToInt.Get(P.String())
	if ok == nil && object != nil {
		return object.(int64)
	}

	mutex.Lock()
	if currentGreatestInt == 0 {
		currentGreatestM = SuiTe.Point().Null()
	}

	BiNeg := SuiTe.Point().Neg(B)
	for Bi, m = currentGreatestM, currentGreatestInt; !Bi.Equal(P) && !SuiTe.Point().Neg(Bi).Equal(P) && m < MaxHomomorphicInt; Bi, m = Bi.Add(Bi, B), m+1 {
		if checkNeg {
			BiNeg := SuiTe.Point().Neg(Bi)
			PointToInt.Put(BiNeg.String(), -m)
		}
		PointToInt.Put(Bi.String(), m)
	}
	currentGreatestM = Bi
	PointToInt.Put(BiNeg.String(), -m)
	PointToInt.Put(Bi.String(), m)
	currentGreatestInt = m

	//no negative responses
	if m == MaxHomomorphicInt {
		return 0
	}
	mutex.Unlock()

	if SuiTe.Point().Neg(Bi).Equal(P) {
		return -m
	}
	return m
}*/

// DeterministicTagging is a distributed deterministic Tagging switching, removes server contribution and multiplies
func (c *CipherText) DeterministicTagging(gc *CipherText, private, secretContrib kyber.Scalar) {
	c.K = SuiTe.Point().Mul(secretContrib, gc.K)

	contrib := SuiTe.Point().Mul(private, gc.K)
	c.C = SuiTe.Point().Sub(gc.C, contrib)
	c.C = SuiTe.Point().Mul(secretContrib, c.C)
}

// DeterministicTagging performs one step in the distributed deterministic Tagging process on a vector
// and stores the result in receiver.
func (cv *CipherVector) DeterministicTagging(cipher *CipherVector, private, secretContrib kyber.Scalar) {
	var wg sync.WaitGroup
	if PARALLELIZE {
		for i := 0; i < len(*cipher); i = i + VPARALLELIZE {
			wg.Add(1)
			go func(i int) {
				for j := 0; j < VPARALLELIZE && (j+i < len(*cipher)); j++ {
					(*cv)[i+j].DeterministicTagging(&(*cipher)[i+j], private, secretContrib)
				}
				defer wg.Done()
			}(i)

		}
		wg.Wait()
	} else {
		for i, c := range *cipher {
			(*cv)[i].DeterministicTagging(&c, private, secretContrib)
		}
	}
}

// TaggingDet performs one step in the distributed deterministic tagging process and creates corresponding proof
func (cv *CipherVector) TaggingDet(privKey, secretContrib kyber.Scalar, pubKey kyber.Point, proofs bool) {
	switchedVect := NewCipherVector(len(*cv))
	switchedVect.DeterministicTagging(cv, privKey, secretContrib)

	if proofs {
		/*p1 := VectorDeterministicTagProofCreation(*cv, *switchedVect, secretContrib, privKey)
		//proof publication
		commitSecret := SuiTe.Point().Mul(secretContrib, SuiTe.Point().Base())
		publishedProof := PublishedDeterministicTaggingProof{Dhp: p1, VectBefore: *cv, VectAfter: *switchedVect, K: pubKey, SB: commitSecret}
		_ = publishedProof*/
	}

	*cv = *switchedVect
}

// ReplaceContribution computes the new CipherText with the old mask contribution replaced by new and save in receiver.
func (c *CipherText) ReplaceContribution(cipher CipherText, old, new kyber.Point) {
	c.C.Sub(cipher.C, old)
	c.C.Add(c.C, new)
}

// KeySwitching performs one step in the Key switching process and stores result in receiver.
func (c *CipherText) KeySwitching(cipher CipherText, originalEphemeralKey, newKey kyber.Point, private kyber.Scalar) kyber.Scalar {
	r := SuiTe.Scalar().Pick(random.New())
	oldContrib := SuiTe.Point().Mul(private, originalEphemeralKey)
	newContrib := SuiTe.Point().Mul(r, newKey)
	ephemContrib := SuiTe.Point().Mul(r, SuiTe.Point().Base())
	c.ReplaceContribution(cipher, oldContrib, newContrib)
	c.K.Add(cipher.K, ephemContrib)
	return r
}

// KeySwitching performs one step in the Key switching process on a vector and stores result in receiver.
func (cv *CipherVector) KeySwitching(cipher CipherVector, originalEphemeralKeys []kyber.Point, newKey kyber.Point, private kyber.Scalar) []kyber.Scalar {
	r := make([]kyber.Scalar, len(*cv))
	var wg sync.WaitGroup
	if PARALLELIZE {
		for i := 0; i < len(cipher); i = i + VPARALLELIZE {
			wg.Add(1)
			go func(i int) {
				for j := 0; j < VPARALLELIZE && (j+i < len(cipher)); j++ {
					r[i+j] = (*cv)[i+j].KeySwitching(cipher[i+j], (originalEphemeralKeys)[i+j], newKey, private)
				}
				defer wg.Done()
			}(i)

		}
		wg.Wait()
	} else {
		for i, c := range cipher {
			r[i] = (*cv)[i].KeySwitching(c, (originalEphemeralKeys)[i], newKey, private)
		}
	}
	return r
}

// Homomorphic operations
//______________________________________________________________________________________________________________________

// Add two ciphertexts and stores result in receiver.
func (c *CipherText) Add(c1, c2 CipherText) {
	c.C.Add(c1.C, c2.C)
	c.K.Add(c1.K, c2.K)
}

// MulCipherTextbyScalar multiplies two components of a ciphertext by a scalar
func (c *CipherText) MulCipherTextbyScalar(cMul CipherText, a kyber.Scalar) {
	c.C = SuiTe.Point().Mul(a, cMul.C)
	c.K = SuiTe.Point().Mul(a, cMul.K)
}

// Add two ciphervectors and stores result in receiver.
func (cv *CipherVector) Add(cv1, cv2 CipherVector) {
	var wg sync.WaitGroup
	if PARALLELIZE {
		for i := 0; i < len(cv1); i = i + VPARALLELIZE {
			wg.Add(1)
			go func(i int) {
				for j := 0; j < VPARALLELIZE && (j+i < len(cv1)); j++ {
					(*cv)[i+j].Add(cv1[i+j], cv2[i+j])
				}
				defer wg.Done()
			}(i)

		}

	} else {
		for i := range cv1 {
			(*cv)[i].Add(cv1[i], cv2[i])
		}
	}
	if PARALLELIZE {
		wg.Wait()
	}
}

// Rerandomize rerandomizes an element in a ciphervector at position j, following the Neff SHuffling algorithm
func (cv *CipherVector) Rerandomize(cv1 CipherVector, a, b kyber.Scalar, ciphert CipherText, g, h kyber.Point, j int) {
	var tmp1, tmp2 kyber.Point
	if ciphert.C == nil {
		//no precomputed value
		tmp1 = SuiTe.Point().Mul(a, g)
		tmp2 = SuiTe.Point().Mul(b, h)
	} else {
		tmp1 = ciphert.K
		tmp2 = ciphert.C
	}

	(*cv)[j].K.Add(cv1[j].K, tmp1)
	(*cv)[j].C.Add(cv1[j].C, tmp2)
}

// Sub two ciphertexts and stores result in receiver.
func (c *CipherText) Sub(c1, c2 CipherText) {
	c.C.Sub(c1.C, c2.C)
	c.K.Sub(c1.K, c2.K)
}

// Sub two cipherVectors and stores result in receiver.
func (cv *CipherVector) Sub(cv1, cv2 CipherVector) {
	for i := range cv1 {
		(*cv)[i].Sub(cv1[i], cv2[i])
	}
}

// Representation
//______________________________________________________________________________________________________________________

// CipherVectorToDeterministicTag creates a tag (grouping key) from a cipher vector
func CipherVectorToDeterministicTag(cipherVect CipherVector, privKey, secContrib kyber.Scalar, pubKey kyber.Point, proofs bool) GroupingKey {
	cipherVect.TaggingDet(privKey, secContrib, pubKey, proofs)
	deterministicGroupAttributes := make(DeterministCipherVector, len(cipherVect))
	for j, c := range cipherVect {
		deterministicGroupAttributes[j] = DeterministCipherText{Point: c.C}
	}
	return deterministicGroupAttributes.Key()
}

// Key is used in order to get a map-friendly representation of grouping attributes to be used as keys.
func (dcv *DeterministCipherVector) Key() GroupingKey {
	var key []string
	for _, a := range *dcv {
		key = append(key, a.String())
	}
	return GroupingKey(strings.Join(key, ""))
}

// Equal checks equality between deterministic ciphervector.
func (dcv *DeterministCipherVector) Equal(dcv2 *DeterministCipherVector) bool {
	if dcv == nil || dcv2 == nil {
		return dcv == dcv2
	}
	for i := range *dcv2 {
		if !(*dcv)[i].Equal(&(*dcv2)[i]) {
			return false
		}
	}
	return true
}

// Equal checks equality between deterministic ciphertexts.
func (dc *DeterministCipherText) Equal(dc2 *DeterministCipherText) bool {
	return dc2.Point.Equal(dc.Point)
}

// String representation of deterministic ciphertext.
func (dc *DeterministCipherText) String() string {
	cstr := "<nil>"
	if (*dc).Point != nil {
		cstr = (*dc).Point.String()
	}
	return fmt.Sprintf("%s", cstr)
}

// String returns a string representation of a ciphertext.
func (c *CipherText) String() string {
	cstr := "nil"
	kstr := cstr
	if (*c).C != nil {
		cstr = (*c).C.String()[1:7]
	}
	if (*c).K != nil {
		kstr = (*c).K.String()[1:7]
	}
	return fmt.Sprintf("CipherText{%s,%s}", kstr, cstr)
}

// RandomScalarSlice creates a random slice of chosen size
func RandomScalarSlice(k int) []kyber.Scalar {
	beta := make([]kyber.Scalar, k)
	rand := SuiTe.RandomStream()
	for i := 0; i < k; i++ {
		beta[i] = SuiTe.Scalar().Pick(rand)
		//beta[i] = SuiTe.Scalar().Zero() to test without shuffle
	}
	return beta
}

// RandomPermutation shuffles a slice of int
func RandomPermutation(k int) []int {
	maxUint := ^uint(0)
	maxInt := int(maxUint >> 1)

	// Pick a random permutation
	pi := make([]int, k)
	rand := SuiTe.RandomStream()
	for i := 0; i < k; i++ {
		// Initialize a trivial permutation
		pi[i] = i
	}
	for i := k - 1; i > 0; i-- {
		randInt := random.Int(big.NewInt(int64(maxInt)), rand)
		// Shuffle by random swaps
		j := int(randInt.Int64()) % (i + 1)
		if j != i {
			t := pi[j]
			pi[j] = pi[i]
			pi[i] = t
		}
	}
	return pi
}

// Conversion
//______________________________________________________________________________________________________________________

// CipherTextByteSize return the length of one CipherText element transform into []byte
func CipherTextByteSize() int {
	return 2 * SuiTe.PointLen()
}

// ToBytes converts a CipherVector to a byte array
func (cv *CipherVector) ToBytes() ([]byte, int) {
	b := make([]byte, 0)

	for _, el := range *cv {
		b = append(b, el.ToBytes()...)
	}

	return b, len(*cv)
}

// FromBytes converts a byte array to a CipherVector. Note that you need to create the (empty) object beforehand.
func (cv *CipherVector) FromBytes(data []byte, length int) {
	*cv = make(CipherVector, length)
	elementSize := CipherTextByteSize()
	for i, pos := 0, 0; i < length*elementSize; i, pos = i+elementSize, pos+1 {
		ct := CipherText{}
		ct.FromBytes(data[i : i+elementSize])
		(*cv)[pos] = ct
	}
}

// ToBytes converts a CipherText to a byte array
func (c *CipherText) ToBytes() []byte {
	k, errK := (*c).K.MarshalBinary()
	if errK != nil {
		log.Fatal(errK)
	}
	cP, errC := (*c).C.MarshalBinary()
	if errC != nil {
		log.Fatal(errC)
	}
	b := append(k, cP...)

	return b
}

// FromBytes converts a byte array to a CipherText. Note that you need to create the (empty) object beforehand.
func (c *CipherText) FromBytes(data []byte) {
	(*c).K = SuiTe.Point()
	(*c).C = SuiTe.Point()

	(*c).K.UnmarshalBinary(data[:SuiTe.PointLen()])
	(*c).C.UnmarshalBinary(data[SuiTe.PointLen():])
}

// Serialize encodes a CipherText in a base64 string
func (c *CipherText) Serialize() string {
	return base64.StdEncoding.EncodeToString((*c).ToBytes())
}

// Deserialize decodes a CipherText from a base64 string
func (c *CipherText) Deserialize(b64Encoded string) error {
	decoded, err := base64.StdEncoding.DecodeString(b64Encoded)
	if err != nil {
		log.Error("Invalid CipherText (decoding failed).", err)
		return err
	}
	(*c).FromBytes(decoded)
	return nil
}

// SerializeElement serializes a BinaryMarshaller-compatible element using base64 encoding (e.g. kyber.Point or kyber.Scalar)
func SerializeElement(el encoding.BinaryMarshaler) (string, error) {
	bytes, err := el.MarshalBinary()
	if err != nil {
		log.Error("Error marshalling element.", err)
		return "", err
	}
	return base64.StdEncoding.EncodeToString(bytes), nil
}

// SerializePoint serializes a point
func SerializePoint(point kyber.Point) (string, error) {
	return SerializeElement(point)
}

// SerializeScalar serializes a scalar
func SerializeScalar(scalar encoding.BinaryMarshaler) (string, error) {
	return SerializeElement(scalar)
}

// DeserializePoint deserializes a point using base64 encoding
func DeserializePoint(encodedPoint string) (kyber.Point, error) {
	decoded, errD := base64.StdEncoding.DecodeString(encodedPoint)
	if errD != nil {
		log.Error("Error decoding point.", errD)
		return nil, errD
	}

	point := SuiTe.Point()
	errM := point.UnmarshalBinary(decoded)
	if errM != nil {
		log.Error("Error unmarshalling point.", errM)
		return nil, errM
	}

	return point, nil
}

// DeserializeScalar deserializes a scalar using base64 encoding
func DeserializeScalar(encodedScalar string) (kyber.Scalar, error) {
	decoded, errD := base64.StdEncoding.DecodeString(encodedScalar)
	if errD != nil {
		log.Error("Error decoding scalar.", errD)
		return nil, errD
	}

	scalar := SuiTe.Scalar()
	errM := scalar.UnmarshalBinary(decoded)
	if errM != nil {
		log.Error("Error unmarshalling scalar.", errM)
		return nil, errM
	}

	return scalar, nil
}

// AbstractPointsToBytes converts an array of kyber.Point to a byte array
func AbstractPointsToBytes(aps []kyber.Point) []byte {
	var err error
	var apsBytes []byte
	response := make([]byte, 0)

	for i := range aps {
		apsBytes, err = aps[i].MarshalBinary()
		if err != nil {
			log.Fatal(err)
		}

		response = append(response, apsBytes...)
	}
	return response
}

// BytesToAbstractPoints converts a byte array to an array of kyber.Point
func BytesToAbstractPoints(target []byte) []kyber.Point {
	var err error
	aps := make([]kyber.Point, 0)

	for i := 0; i < len(target); i += 32 {
		ap := SuiTe.Point()
		if err = ap.UnmarshalBinary(target[i : i+32]); err != nil {
			log.Fatal(err)
		}

		aps = append(aps, ap)
	}
	return aps
}
