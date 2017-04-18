package services

import (
	"github.com/JoaoAndreSa/MedCo/lib"
	"github.com/JoaoAndreSa/MedCo/services/data"
	"github.com/Knetic/govaluate"
	"github.com/btcsuite/goleveldb/leveldb/errors"
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/dedis/onet.v1/network"
	"os"
	"strconv"
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

// PrecomputeForShuffling precomputes data to be used in the shuffling protocol (to make it faster) and saves it in a .gob file
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

// PrecomputationWritingForShuffling reads the precomputation data from  .gob file if it already exists or generates a new one
func PrecomputationWritingForShuffling(appFlag bool, gobFile, serverName string, surveySecret abstract.Scalar, collectiveKey abstract.Point, lineSize int) []lib.CipherVectorScalar {
	log.Lvl1(serverName, " precomputes for shuffling")
	precomputeShuffle := []lib.CipherVectorScalar{}
	if appFlag {
		if _, err := os.Stat(gobFile); os.IsNotExist(err) {
			precomputeShuffle = PrecomputeForShuffling(serverName, gobFile, surveySecret, collectiveKey, lineSize)
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

// ReadPrecomputedFile reads the precomputation data from a .gob file
func ReadPrecomputedFile(fileName string) []lib.CipherVectorScalar {
	precomputeShuffle := []lib.CipherVectorScalar{}
	if _, err := os.Stat(fileName); !os.IsNotExist(err) {
		var encoded []lib.CipherVectorScalarBytes
		data.ReadFromGobFile(fileName, &encoded)

		precomputeShuffle, _ = data.DecodeCipherVectorScalar(encoded)
	} else {
		precomputeShuffle = nil
	}
	return precomputeShuffle
}

// FilterResponses evaluates the predicate and keeps the entries that satisfy the conditions
func FilterResponses(pred string, whereQueryValues []lib.WhereQueryAttributeTagged, responsesToFilter []lib.ProcessResponseDet) []lib.FilteredResponseDet {
	result := []lib.FilteredResponseDet{}
	for _, v := range responsesToFilter {
		expression, err := govaluate.NewEvaluableExpression(pred)
		if err != nil {
			return result
		}
		parameters := make(map[string]interface{}, len(whereQueryValues)+len(responsesToFilter[0].DetTagWhere))
		counter := 0
		for i := 0; i < len(whereQueryValues)+len(responsesToFilter[0].DetTagWhere); i++ {

			if i%2 == 0 {
				parameters["v"+strconv.Itoa(i)] = string(whereQueryValues[counter].Value)
			} else {
				parameters["v"+strconv.Itoa(i)] = string(v.DetTagWhere[counter])
				counter++
			}

		}

		keep, err := expression.Evaluate(parameters)
		if keep.(bool) {
			result = append(result, lib.FilteredResponseDet{DetTagGroupBy: v.DetTagGroupBy, Fr: lib.FilteredResponse{GroupByEnc: v.PR.GroupByEnc, AggregatingAttributes: v.PR.AggregatingAttributes}})
		}
	}
	return result
}

// CountDPs counts the number of data providers targeted by a query/survey
func CountDPs(m map[string]int64) int64 {
	result := int64(0)
	for _, v := range m {
		result += v
	}
	return result
}
