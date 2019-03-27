package libunlynxtools

import (
	"encoding/binary"
	"encoding/gob"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/btcsuite/goleveldb/leveldb/errors"
	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
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

// UnsafeCastIntsToBytes casts a slice of ints to a slice of bytes
func UnsafeCastIntsToBytes(ints []int) []byte {
	bsFinal := make([]byte, 0)
	for _, num := range ints {
		buf := make([]byte, 4)
		binary.BigEndian.PutUint32(buf, uint32(num))
		bsFinal = append(bsFinal, buf...)
	}
	return bsFinal
}

// UnsafeCastBytesToInts casts a slice of bytes to a slice of ints
func UnsafeCastBytesToInts(bytes []byte) []int {
	intsFinal := make([]int, 0)
	for i := 0; i < len(bytes); i += 4 {
		x := binary.BigEndian.Uint32(bytes[i : i+4])
		intsFinal = append(intsFinal, int(x))
	}
	return intsFinal
}

// Int64ArrayToString transforms an integer array into a string
func Int64ArrayToString(s []int64) string {
	if len(s) == 0 {
		return ""
	}

	result := ""
	for _, elem := range s {
		result += fmt.Sprintf("%v ", elem)
	}
	return result
}

// StringToInt64Array transforms a string ("1 0 1 0") to an integer array
func StringToInt64Array(s string) []int64 {
	if len(s) == 0 {
		return make([]int64, 0)
	}

	container := strings.Split(s, " ")

	result := make([]int64, 0)
	for _, elem := range container {
		if elem != "" {
			aux, _ := strconv.ParseInt(elem, 10, 64)
			result = append(result, aux)
		}
	}
	return result
}

// ConvertDataToMap a converts an array of integers to a map of id -> integer
func ConvertDataToMap(data []int64, first string, start int) map[string]int64 {
	result := make(map[string]int64)
	for _, el := range data {
		result[first+strconv.Itoa(start)] = el
		start++
	}
	return result
}

// ConvertMapToData converts the map into a slice of int64 (to ease out printing and aggregation)
func ConvertMapToData(data map[string]int64, first string, start int) []int64 {
	result := make([]int64, len(data))
	for i := 0; i < len(data); i++ {
		result[i] = data[first+strconv.Itoa(start)]
		start++
	}
	return result
}

// WriteToGobFile stores object (e.g. lib.Enc_CipherVectorScalar) in a gob file. Note that the object must contain serializable stuff, for example byte arrays.
func WriteToGobFile(path string, object interface{}) {
	file, err := os.Create(path)
	defer file.Close()

	if err == nil {
		encoder := gob.NewEncoder(file)
		if err := encoder.Encode(object); err != nil {
			log.Fatal(err)
		}
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
