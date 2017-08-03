package lib

import (
	"encoding"
	"encoding/base64"
	"fmt"
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/crypto.v0/random"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/dedis/onet.v1/network"
	"strings"
	"sync"
)

// MaxHomomorphicInt is upper bound for integers used in messages, a failed decryption will return this value.
const MaxHomomorphicInt int64 = 100000

// PointToInt creates a map between EC points and integers.
var PointToInt = make(map[string]int64, MaxHomomorphicInt)
var currentGreatestM abstract.Point
var currentGreatestInt int64
var suite = network.Suite

// CipherText is an ElGamal encrypted point.
type CipherText struct {
	K, C abstract.Point
}

// CipherVector is a slice of ElGamal encrypted points.
type CipherVector []CipherText

// DeterministCipherText deterministic encryption of a point.
type DeterministCipherText struct {
	Point abstract.Point
}

// DeterministCipherVector slice of deterministic encrypted points.
type DeterministCipherVector []DeterministCipherText

// Constructors
//______________________________________________________________________________________________________________________

// NewCipherText creates a ciphertext of null elements.
func NewCipherText() *CipherText {
	return &CipherText{K: suite.Point().Null(), C: suite.Point().Null()}
}

// NewCipherTextFromBase64 creates a ciphertext of null elements.
func NewCipherTextFromBase64(b64Encoded string) *CipherText {
	cipherText := &CipherText{K: suite.Point().Null(), C: suite.Point().Null()}
	(*cipherText).Deserialize(b64Encoded)
	return cipherText
}

// NewCipherVector creates a ciphervector of null elements.
func NewCipherVector(length int) *CipherVector {
	cv := make(CipherVector, length)
	for i := 0; i < length; i++ {
		cv[i] = CipherText{suite.Point().Null(), suite.Point().Null()}
	}
	return &cv
}

// NewDeterministicCipherText create determinist cipher text of null element.
func NewDeterministicCipherText() *DeterministCipherText {
	dc := DeterministCipherText{suite.Point().Null()}
	return &dc
}

// NewDeterministicCipherVector creates a vector of determinist ciphertext of null elements.
func NewDeterministicCipherVector(length int) *DeterministCipherVector {
	dcv := make(DeterministCipherVector, length)
	for i := 0; i < length; i++ {
		dcv[i] = DeterministCipherText{suite.Point().Null()}
	}
	return &dcv
}

// Key Pairs (mostly used in tests)
//----------------------------------------------------------------------------------------------------------------------

// GenKey permits to generate a public/private key pairs.
func GenKey() (secKey abstract.Scalar, pubKey abstract.Point) {
	secKey = suite.Scalar().Pick(random.Stream)
	pubKey = suite.Point().Mul(suite.Point().Base(), secKey)
	return
}

// GenKeys permits to generate ElGamal public/private key pairs.
func GenKeys(n int) (abstract.Point, []abstract.Scalar, []abstract.Point) {
	priv := make([]abstract.Scalar, n)
	pub := make([]abstract.Point, n)
	group := suite.Point().Null()
	for i := 0; i < n; i++ {
		priv[i], pub[i] = GenKey()
		group.Add(group, pub[i])
	}
	return group, priv, pub
}

// Encryption
//______________________________________________________________________________________________________________________

// encryptPoint creates an elliptic curve point from a non-encrypted point and encrypt it using ElGamal encryption.
func encryptPoint(pubkey abstract.Point, M abstract.Point) *CipherText {
	B := suite.Point().Base()
	k := suite.Scalar().Pick(random.Stream) // ephemeral private key
	// ElGamal-encrypt the point to produce ciphertext (K,C).
	K := suite.Point().Mul(B, k)      // ephemeral DH public key
	S := suite.Point().Mul(pubkey, k) // ephemeral DH shared secret
	C := S.Add(S, M)                  // message blinded with secret
	return &CipherText{K, C}
}

// IntToPoint maps an integer to a point in the elliptic curve
func IntToPoint(integer int64) abstract.Point {
	B := suite.Point().Base()
	i := suite.Scalar().SetInt64(integer)
	M := suite.Point().Mul(B, i)
	return M
}

// PointToCipherText converts a point into a ciphertext
func PointToCipherText(point abstract.Point) CipherText {
	return CipherText{K: suite.Point().Null(), C: point}
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
func EncryptInt(pubkey abstract.Point, integer int64) *CipherText {
	return encryptPoint(pubkey, IntToPoint(integer))
}

// EncryptIntVector encrypts a []int into a CipherVector and returns a pointer to it.
func EncryptIntVector(pubkey abstract.Point, intArray []int64) *CipherVector {
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

// NullCipherVector encrypts an 0-filled slice under the given public key.
func NullCipherVector(length int, pubkey abstract.Point) *CipherVector {
	return EncryptIntVector(pubkey, make([]int64, length))
}

// Decryption
//______________________________________________________________________________________________________________________

// decryptPoint decrypts an elliptic point from an El-Gamal cipher text.
func decryptPoint(prikey abstract.Scalar, c CipherText) abstract.Point {
	S := suite.Point().Mul(c.K, prikey) // regenerate shared secret
	M := suite.Point().Sub(c.C, S)      // use to un-blind the message
	return M
}

// DecryptInt decrypts an integer from an ElGamal cipher text where integer are encoded in the exponent.
func DecryptInt(prikey abstract.Scalar, cipher CipherText) int64 {
	M := decryptPoint(prikey, cipher)
	return discreteLog(M)
}

// DecryptIntVector decrypts a cipherVector.
func DecryptIntVector(prikey abstract.Scalar, cipherVector *CipherVector) []int64 {
	result := make([]int64, len(*cipherVector))
	for i, c := range *cipherVector {
		result[i] = DecryptInt(prikey, c)
	}
	return result
}

// Brute-Forces the discrete log for integer decoding.
func discreteLog(P abstract.Point) int64 {
	B := suite.Point().Base()
	var Bi abstract.Point
	var m int64
	var ok bool

	if m, ok = PointToInt[P.String()]; ok {
		return m
	}

	if currentGreatestInt == 0 {
		currentGreatestM = suite.Point().Null()
	}

	for Bi, m = currentGreatestM, currentGreatestInt; !Bi.Equal(P) && m < MaxHomomorphicInt; Bi, m = Bi.Add(Bi, B), m+1 {
		PointToInt[Bi.String()] = m
	}
	currentGreatestM = Bi
	PointToInt[Bi.String()] = m
	currentGreatestInt = m

	//no negative responses
	if m == MaxHomomorphicInt {
		return 0
	}
	return m
}

// DeterministicTagging is a distributed deterministic Tagging switching, removes server contribution and multiplies
func (c *CipherText) DeterministicTagging(gc *CipherText, private, secretContrib abstract.Scalar) {
	c.K = suite.Point().Mul(gc.K, secretContrib)

	contrib := suite.Point().Mul(gc.K, private)
	c.C = suite.Point().Sub(gc.C, contrib)
	c.C = suite.Point().Mul(c.C, secretContrib)
}

// DeterministicTagging performs one step in the distributed deterministic Tagging process on a vector
// and stores the result in receiver.
func (cv *CipherVector) DeterministicTagging(cipher *CipherVector, private, secretContrib abstract.Scalar) {
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
func (cv *CipherVector) TaggingDet(privKey, secretContrib abstract.Scalar, pubKey abstract.Point, proofs bool) {
	switchedVect := NewCipherVector(len(*cv))
	switchedVect.DeterministicTagging(cv, privKey, secretContrib)

	if proofs {
		p1 := VectorDeterministicTagProofCreation(*cv, *switchedVect, secretContrib, privKey)
		//proof publication
		commitSecret := suite.Point().Mul(suite.Point().Base(), secretContrib)
		publishedProof := PublishedDeterministicTaggingProof{Dhp: p1, VectBefore: *cv, VectAfter: *switchedVect, K: pubKey, SB: commitSecret}
		_ = publishedProof
	}

	*cv = *switchedVect
}

// ReplaceContribution computes the new CipherText with the old mask contribution replaced by new and save in receiver.
func (c *CipherText) ReplaceContribution(cipher CipherText, old, new abstract.Point) {
	c.C.Sub(cipher.C, old)
	c.C.Add(c.C, new)
}

// KeySwitching performs one step in the Key switching process and stores result in receiver.
func (c *CipherText) KeySwitching(cipher CipherText, originalEphemeralKey, newKey abstract.Point, private abstract.Scalar) abstract.Scalar {
	r := suite.Scalar().Pick(random.Stream)
	oldContrib := suite.Point().Mul(originalEphemeralKey, private)
	newContrib := suite.Point().Mul(newKey, r)
	ephemContrib := suite.Point().Mul(suite.Point().Base(), r)
	c.ReplaceContribution(cipher, oldContrib, newContrib)
	c.K.Add(cipher.K, ephemContrib)
	return r
}

// KeySwitching performs one step in the Key switching process on a vector and stores result in receiver.
func (cv *CipherVector) KeySwitching(cipher CipherVector, originalEphemeralKeys []abstract.Point, newKey abstract.Point, private abstract.Scalar) []abstract.Scalar {
	r := make([]abstract.Scalar, len(*cv))
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
func (c *CipherText) MulCipherTextbyScalar(cMul CipherText, a abstract.Scalar) {
	c.C = suite.Point().Mul(cMul.C, a)
	c.K = suite.Point().Mul(cMul.K, a)
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
func (cv *CipherVector) Rerandomize(cv1 CipherVector, a, b abstract.Scalar, ciphert CipherText, g, h abstract.Point, j int) {
	var tmp1, tmp2 abstract.Point
	if ciphert.C == nil {
		//no precomputed value
		tmp1 = suite.Point().Mul(g, a)
		tmp2 = suite.Point().Mul(h, b)
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
func CipherVectorToDeterministicTag(cipherVect CipherVector, privKey, secContrib abstract.Scalar, pubKey abstract.Point, proofs bool) GroupingKey {
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
func RandomScalarSlice(k int) []abstract.Scalar {
	beta := make([]abstract.Scalar, k)
	rand := suite.Cipher(abstract.RandomKey)
	for i := 0; i < k; i++ {
		beta[i] = suite.Scalar().Pick(rand)
		//beta[i] = suite.Scalar().Zero() to test without shuffle
	}
	return beta
}

// RandomPermutation shuffles a slice of int
func RandomPermutation(k int) []int {
	// Pick a random permutation
	pi := make([]int, k)
	rand := suite.Cipher(abstract.RandomKey)
	for i := 0; i < k; i++ {
		// Initialize a trivial permutation
		pi[i] = i
	}
	for i := k - 1; i > 0; i-- {
		// Shuffle by random swaps
		j := int(random.Uint64(rand) % uint64(i+1))
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
	(*cv) = make(CipherVector, length)
	for i, pos := 0, 0; i < length*64; i, pos = i+64, pos+1 {
		ct := CipherText{}
		ct.FromBytes(data[i : i+64])
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
	(*c).K = suite.Point()
	(*c).C = suite.Point()

	(*c).K.UnmarshalBinary(data[:32])
	(*c).C.UnmarshalBinary(data[32:])
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

// SerializeElement serializes a BinaryMarshaller-compatible element using base64 encoding (e.g. abstract.Point or abstract.Scalar)
func SerializeElement(el encoding.BinaryMarshaler) (string, error) {
	bytes, err := el.MarshalBinary()
	if err != nil {
		log.Error("Error marshalling element.", err)
		return "", err
	}
	return base64.StdEncoding.EncodeToString(bytes), nil
}

// SerializePoint serializes a point
func SerializePoint(point abstract.Point) (string, error) {
	return SerializeElement(point)
}

// SerializeScalar serializes a scalar
func SerializeScalar(scalar encoding.BinaryMarshaler) (string, error) {
	return SerializeElement(scalar)
}

// DeserializePoint deserializes a point using base64 encoding
func DeserializePoint(encodedPoint string) (abstract.Point, error) {
	decoded, errD := base64.StdEncoding.DecodeString(encodedPoint)
	if errD != nil {
		log.Error("Error decoding point.", errD)
		return nil, errD
	}

	point := network.Suite.Point()
	errM := point.UnmarshalBinary(decoded)
	if errM != nil {
		log.Error("Error unmarshalling point.", errM)
		return nil, errM
	}

	return point, nil
}

// DeserializeScalar deserializes a scalar using base64 encoding
func DeserializeScalar(encodedScalar string) (abstract.Scalar, error) {
	decoded, errD := base64.StdEncoding.DecodeString(encodedScalar)
	if errD != nil {
		log.Error("Error decoding scalar.", errD)
		return nil, errD
	}

	scalar := network.Suite.Scalar()
	errM := scalar.UnmarshalBinary(decoded)
	if errM != nil {
		log.Error("Error unmarshalling scalar.", errM)
		return nil, errM
	}

	return scalar, nil
}

// AbstractPointsToBytes converts an array of abstract.Point to a byte array
func AbstractPointsToBytes(aps []abstract.Point) []byte {
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

// BytesToAbstractPoints converts a byte array to an array of abstract.Point
func BytesToAbstractPoints(target []byte) []abstract.Point {
	var err error
	aps := make([]abstract.Point, 0)

	for i := 0; i < len(target); i += 32 {
		ap := network.Suite.Point()
		if err = ap.UnmarshalBinary(target[i : i+32]); err != nil {
			log.Fatal(err)
		}

		aps = append(aps, ap)
	}
	return aps
}
