package services

import (
	"github.com/JoaoAndreSa/MedCo/lib"
	"github.com/JoaoAndreSa/MedCo/services/data"
	"github.com/btcsuite/goleveldb/leveldb/errors"
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/dedis/onet.v1/network"
	"os"
	"strings"
)

// SendISMOthers sends a message to all other services
func SendISMOthers(s *onet.ServiceProcessor, el *onet.Roster, msg interface{}) error {
	var errStrs []string
	for _, e := range el.List {
		if !e.ID.Equal(s.ServerIdentity().ID) {
			log.Lvl3("Sending to", e)
			err := s.SendRaw(e, msg)
			if err != nil {
				errStrs = append(errStrs, err.Error())
			}
		}
	}
	var err error
	if len(errStrs) > 0 {
		err = errors.New(strings.Join(errStrs, "\n"))
	}
	return err
}

func PrecomputeForShuffling(serverName, gobFile string, surveySecret abstract.Scalar, collectiveKey abstract.Point, lineSize int) []lib.CipherVectorScalar {
	log.Lvl1(serverName, " precomputes for shuffling")
	precomputeShuffle := lib.CreatePrecomputedRandomize(network.Suite.Point().Base(), collectiveKey, network.Suite.Cipher(surveySecret.Bytes()), lineSize*2, 10)

	encoded, err := data.EncodeCipherVectorScalar(precomputeShuffle)

	if err != nil {
		log.Fatal("Error during marshaling")
	}
	data.WriteToGobFile(gobFile, encoded)

	return precomputeShuffle
}

func PrecomputationWritingForShuffling(appFlag bool, gobFile, serverName string, surveySecret abstract.Scalar, collectiveKey abstract.Point, lineSize int) []lib.CipherVectorScalar {
	log.Lvl1(serverName, " precomputes for shuffling")
	precomputeShuffle := []lib.CipherVectorScalar{}
	if appFlag {
		if _, err := os.Stat(gobFile); os.IsNotExist(err) {

			PrecomputeForShuffling(serverName, gobFile, surveySecret, collectiveKey, lineSize)
		} else {
			var encoded []lib.CipherVectorScalarBytes
			data.ReadFromGobFile(gobFile, &encoded)

			precomputeShuffle, err = data.DecodeCipherVectorScalar(encoded)

			if len(precomputeShuffle[0].CipherV) < lineSize {

			}
			if err != nil {
				log.Fatal("Error during unmarshaling")
			}
		}
	} else {
		precomputeShuffle = lib.CreatePrecomputedRandomize(network.Suite.Point().Base(), collectiveKey, network.Suite.Cipher(surveySecret.Bytes()), lineSize*2, 10)
	}
	return precomputeShuffle
}
