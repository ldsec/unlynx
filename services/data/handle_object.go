package data

import (
	"encoding/gob"
	"os"

	"github.com/JoaoAndreSa/MedCo/lib"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/dedis/onet.v1/network"
)

// WriteToGobFile stores object (e.g. lib.Enc_CipherVectorScalar) in a gob file. Note that the object must contain serializable stuff, for example byte arrays.
func WriteToGobFile(path string, object interface{}) {
	file, err := os.Create(path)
	defer file.Close()

	if err == nil {
		encoder := gob.NewEncoder(file)
		encoder.Encode(object)
	} else {
		log.Fatal("Could not write Gob file: ", err)
	}
}

// ReadFromGobFile reads data from gob file to the object
func ReadFromGobFile(path string, object interface{}) {
	file, err := os.Open(path)
	defer file.Close()

	if err == nil {
		decoder := gob.NewDecoder(file)
		err = decoder.Decode(object)
	} else {
		log.Fatal("Could not read Gob file: ", err)
	}
}

// EncodeCipherVectorScalar converts the data inside lib.CipherVectorScalar to bytes and stores it in a new object to be saved in the gob file
func EncodeCipherVectorScalar(cV []lib.CipherVectorScalar) ([]lib.CipherVectorScalarBytes, error) {
	slice := make([]lib.CipherVectorScalarBytes, 0)

	for _, v := range cV {
		eCV := lib.CipherVectorScalarBytes{}

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
func DecodeCipherVectorScalar(eCV []lib.CipherVectorScalarBytes) ([]lib.CipherVectorScalar, error) {
	slice := make([]lib.CipherVectorScalar, 0)

	for _, v := range eCV {
		cV := lib.CipherVectorScalar{}

		for _, el := range v.S {
			s := network.Suite.Scalar()
			if err := s.UnmarshalBinary(el); err != nil {
				return slice, err
			}

			cV.S = append(cV.S, s)
		}

		for _, el := range v.CipherV {
			k := network.Suite.Point()
			if err := k.UnmarshalBinary(el[0]); err != nil {
				return slice, err
			}

			c := network.Suite.Point()
			if err := c.UnmarshalBinary(el[1]); err != nil {
				return slice, err
			}

			cipher := lib.CipherText{K: k, C: c}
			cV.CipherV = append(cV.CipherV, cipher)

		}

		slice = append(slice, cV)
	}

	return slice, nil
}
