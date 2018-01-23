package services

import (
	"github.com/Knetic/govaluate"
	"github.com/btcsuite/goleveldb/leveldb/errors"
	"github.com/lca1/unlynx/lib"
	"github.com/lca1/unlynx/services/data"
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
		log.Error("Error during marshaling")
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
				log.Error("Error during unmarshaling")
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

// FilterResponsesMedCo evaluates the predicate and keeps the entries that satisfy the conditions
// arguments examples
// pred: (exists(v1, r)) && (exists(v2, r) || exists(v3, r))
// whereQueryValues: [v1_enc_value, v2_enc_value, v3_enc_value]
func FilterResponsesMedCo(pred string, whereQueryValues []lib.WhereQueryAttributeTagged, responsesToFilter []lib.ProcessResponseDet, pubKey abstract.Point) []lib.FilteredResponseDet {
	// TODO: whereQueryValues.Name not used anymore

	result := []lib.FilteredResponseDet{}

	// declare "exists" function to use within govaluate expressions
	govaluateFunctions := map[string]govaluate.ExpressionFunction{

		/*
			args[0]: string, encrypted value to search
			args[1]: int, id of the response to look into
		*/
		"exists": func(args ...interface{}) (interface{}, error) {
			toSearch := args[0].(string)
			responseID, err := strconv.Atoi(args[1].(string))

			// linear search and no sorting done: values to search in are supposed few,
			// but the search operation is done many times => probably not worth it to sort it every time
			// XXX if perf bottleneck: if we can assume it comes sorted already, can become better
			for _, setValue := range responsesToFilter[responseID].DetTagWhere {
				if string(setValue) == toSearch {
					return true, err
				}
			}

			return false, err
		},
	}

	// load expression in govaluate
	expression, err := govaluate.NewEvaluableExpressionWithFunctions(pred, govaluateFunctions)
	if err != nil {
		return result
	}

	// evaluate on each response the predicate
	// e.g.: 1 row = [ [ ] [E(cancer), E(dead), ...] [1] ] = per patient
	for responseID := 0; responseID < len(responsesToFilter); responseID++ {

		// generate parameters for govaluate
		parameters := make(map[string]interface{}, 1+len(whereQueryValues))
		parameters["r"] = strconv.Itoa(responseID)
		for i := 0; i < len(whereQueryValues); i++ {
			parameters["v"+strconv.Itoa(i)] = string(whereQueryValues[i].Value)
		}

		keep, err := expression.Evaluate(parameters)
		if err != nil {
			//XXX: better error handling?
			log.Error("Could not evaluate the expression.", err)
			return result
		}

		if keep.(bool) {
			result = append(result, lib.FilteredResponseDet{
				DetTagGroupBy: responsesToFilter[responseID].DetTagGroupBy,
				Fr: lib.FilteredResponse{
					GroupByEnc:            responsesToFilter[responseID].PR.GroupByEnc,
					AggregatingAttributes: responsesToFilter[responseID].PR.AggregatingAttributes}})
		}
	}

	if len(result) == 0 {
		zeroAnswer := make(lib.CipherVector, 0)
		zeroAnswer = append(zeroAnswer, *lib.EncryptInt(pubKey, 0))

		result = append(result, lib.FilteredResponseDet{
			DetTagGroupBy: lib.GroupingKey(""),
			Fr: lib.FilteredResponse{
				GroupByEnc:            make(lib.CipherVector, 0),
				AggregatingAttributes: zeroAnswer}})
	}

	return result
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

// FilterNone skips the filtering of attributes when there is no predicate (the number of where attributes == 0)
func FilterNone(responsesToFilter []lib.ProcessResponseDet) []lib.FilteredResponseDet {
	result := []lib.FilteredResponseDet{}
	for _, v := range responsesToFilter {
		result = append(result, lib.FilteredResponseDet{DetTagGroupBy: v.DetTagGroupBy, Fr: lib.FilteredResponse{GroupByEnc: v.PR.GroupByEnc, AggregatingAttributes: v.PR.AggregatingAttributes}})
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
