package libunlynxshuffle

import (
	"github.com/ldsec/unlynx/lib"
	"go.dedis.ch/kyber/v3"
)

// Structs
//______________________________________________________________________________________________________________________

// CipherVectorScalar contains the elements forming precomputed values for shuffling, a CipherVector and the scalars
// corresponding to each element
type CipherVectorScalar struct {
	CipherV libunlynx.CipherVector
	S       []kyber.Scalar
}

// CipherVectorScalarBytes is a CipherVectorScalar in bytes
type CipherVectorScalarBytes struct {
	CipherV [][][]byte
	S       [][]byte
}

// Conversion
//______________________________________________________________________________________________________________________

// EncodeCipherVectorScalar converts the data inside lib.CipherVectorScalar to bytes and stores it in a new object to be saved in the gob file
func EncodeCipherVectorScalar(cV []CipherVectorScalar) ([]CipherVectorScalarBytes, error) {
	slice := make([]CipherVectorScalarBytes, 0)

	for _, v := range cV {
		eCV := CipherVectorScalarBytes{}

		for _, el := range v.S {
			scalar, err := el.MarshalBinary()

			if err != nil {
				return slice, err
			}

			eCV.S = append(eCV.S, scalar)
		}

		for _, el := range v.CipherV {
			container := make([][]byte, 0)

			c, err := el.C.MarshalBinary()

			if err != nil {
				return slice, err
			}

			k, err := el.K.MarshalBinary()

			if err != nil {
				return slice, err
			}

			container = append(container, k, c)

			eCV.CipherV = append(eCV.CipherV, container)
		}

		slice = append(slice, eCV)
	}

	return slice, nil
}

// DecodeCipherVectorScalar converts the byte data stored in the lib.Enc_CipherVectorScalar (which is read from the gob file) to a new lib.CipherVectorScalar
func DecodeCipherVectorScalar(eCV []CipherVectorScalarBytes) ([]CipherVectorScalar, error) {
	slice := make([]CipherVectorScalar, 0)

	for _, v := range eCV {
		cV := CipherVectorScalar{}

		for _, el := range v.S {
			s := libunlynx.SuiTe.Scalar()
			if err := s.UnmarshalBinary(el); err != nil {
				return slice, err
			}

			cV.S = append(cV.S, s)
		}

		for _, el := range v.CipherV {
			k := libunlynx.SuiTe.Point()
			if err := k.UnmarshalBinary(el[0]); err != nil {
				return slice, err
			}

			c := libunlynx.SuiTe.Point()
			if err := c.UnmarshalBinary(el[1]); err != nil {
				return slice, err
			}

			cipher := libunlynx.CipherText{K: k, C: c}
			cV.CipherV = append(cV.CipherV, cipher)

		}

		slice = append(slice, cV)
	}

	return slice, nil
}
