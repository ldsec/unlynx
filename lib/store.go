package lib

import (
	"fmt"
	"strconv"
	"strings"
	"sync"

	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/onet.v1/log"
)

// Store contains all the elements of a survey, it consists of the data structure that each cothority has to
// maintain locally to perform a collective survey.
type Store struct {
	DpResponses             []ProcessResponse
	DeliverableResults      []FilteredResponse
	ShuffledClientResponses []ProcessResponse

	dpResponsesAggr map[GroupingKeyTuple]DpResponse
	// LocGroupingAggregating contains the results of the local aggregation.
	LocAggregatedClientResponse map[GroupingKey]FilteredResponse

	Mutex sync.Mutex

	// GroupedDeterministicGroupingAttributes & GroupedAggregatingAttributes contain results of the grouping
	// before they are key switched and combined in the last step (key switching).
	GroupedDeterministicClientResponses map[GroupingKey]FilteredResponse

	lastID uint64
}

type GroupingKeyTuple struct {
	gkt1 GroupingKey
	gkt2 GroupingKey
}

// NewStore is the store constructor.
func NewStore() *Store {
	return &Store{
		dpResponsesAggr:                     make(map[GroupingKeyTuple]DpResponse),
		LocAggregatedClientResponse:         make(map[GroupingKey]FilteredResponse),
		GroupedDeterministicClientResponses: make(map[GroupingKey]FilteredResponse),
	}
}

// InsertClientResponse handles the local storage of a new client response in aggregation or grouping cases.
func (s *Store) InsertDpResponse(cr DpResponse, pubKey abstract.Point) {
	if cr.WhereEnc != nil || cr.GroupByEnc != nil {
		newResp := ProcessResponse{}
		newResp.GroupByEnc = append(*EncryptIntVector(pubKey, cr.GroupByClear), cr.GroupByEnc...)
		newResp.WhereEnc = append(*EncryptIntVector(pubKey, cr.WhereClear), cr.WhereEnc...)
		log.LLvl1("STORE ", newResp.WhereEnc)
		newResp.AggregatingAttributes = cr.AggregatingAttributes
		s.DpResponses = append(s.DpResponses, newResp)
	} else {
		value, ok := s.dpResponsesAggr[GroupingKeyTuple{Key(cr.GroupByClear), Key(cr.WhereClear)}]
		if ok {
			tmp := *NewCipherVector(len(value.AggregatingAttributes)).Add(value.AggregatingAttributes, cr.AggregatingAttributes)
			mapValue := s.dpResponsesAggr[GroupingKeyTuple{Key(cr.GroupByClear), Key(cr.WhereClear)}]
			mapValue.AggregatingAttributes = tmp
			s.dpResponsesAggr[GroupingKeyTuple{Key(cr.GroupByClear), Key(cr.WhereClear)}] = mapValue
		} else {
			s.dpResponsesAggr[GroupingKeyTuple{Key(cr.GroupByClear), Key(cr.WhereClear)}] = cr
		}
	}

}

// HasNextClientResponse permits to verify if there are new client responses to be processed.
func (s *Store) HasNextClientResponse() bool {
	return len(s.DpResponses) > 0
}

// PullClientResponses permits to get the received client responses
func (s *Store) PullDpResponses(pubKey abstract.Point) []ProcessResponse {
	result := []ProcessResponse{}
	if len(s.DpResponses) > 0 {
		result = s.DpResponses
	} else {
		for _, v := range s.dpResponsesAggr {
			//TODO function
			newResp := ProcessResponse{}
			newResp.GroupByEnc = append(*EncryptIntVector(pubKey, v.GroupByClear), v.GroupByEnc...)
			newResp.WhereEnc = append(*EncryptIntVector(pubKey, v.WhereClear), v.WhereEnc...)
			newResp.AggregatingAttributes = v.AggregatingAttributes
			result = append(result, newResp)
		}
	}

	s.DpResponses = s.DpResponses[:0] //clear table
	return result
}

// PushShuffledClientResponses stores shuffled responses
func (s *Store) PushShuffledClientResponses(newShuffledClientResponses []ProcessResponse) {
	s.ShuffledClientResponses = append(s.ShuffledClientResponses, newShuffledClientResponses...)
}

// PullShuffledClientResponses gets shuffled client responses
func (s *Store) PullShuffledClientResponses() []ProcessResponse {
	result := s.ShuffledClientResponses
	s.ShuffledClientResponses = s.ShuffledClientResponses[:0] //clear table
	return result
}

// PushDeterministicClientResponses permits to store results of deterministic tagging
func (s *Store) PushDeterministicClientResponses(detClientResponses []FilteredResponseDet, serverName string, proofs bool) {

	round := StartTimer(serverName + "_ServerLocalAggregation")

	for _, v := range detClientResponses {
		s.Mutex.Lock()
		AddInMap(s.LocAggregatedClientResponse, v.DetTagGroupBy, v.Fr)
		s.Mutex.Unlock()
	}
	/*if proofs {	//TODO: Uncomment
		PublishedAggregationProof := AggregationProofCreation(detClientResponses, s.LocAggregatedClientResponse)
		//publication
		_ = PublishedAggregationProof
	}*/
	EndTimer(round)
}

// HasNextAggregatedResponse verifies the presence of locally aggregated results.
func (s *Store) HasNextAggregatedResponse() bool {
	return len(s.LocAggregatedClientResponse) > 0
}

// PullLocallyAggregatedResponses permits to get the result of the collective and grouped aggregation
func (s *Store) PullLocallyAggregatedResponses() map[GroupingKey]FilteredResponse {
	LocGroupingAggregatingReturn := s.LocAggregatedClientResponse
	s.LocAggregatedClientResponse = make(map[GroupingKey]FilteredResponse)
	return LocGroupingAggregatingReturn

}

func (s *Store) nextID() TempID {
	s.lastID++
	return TempID(s.lastID)
}

// AddInMap permits to add a client response with its deterministic tag in a map
func AddInMap(s map[GroupingKey]FilteredResponse, key GroupingKey, added FilteredResponse) {
	if localResult, ok := s[key]; !ok {
		s[key] = added
	} else {
		tmp := NewClientResponse(len(added.GroupByEnc), len(added.AggregatingAttributes))
		s[key] = *tmp.Add(localResult, added)
	}
}

// int64ArrayToString transforms an array into a string
func int64ArrayToString(s []int64) string {
	if len(s) == 0 {
		return ""
	}

	result := ""
	for _, elem := range s {
		result += fmt.Sprintf("%v ", elem)
	}
	return result[:len(result)-1]
}

// StringToInt64Array transforms an array to a string
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

// AddInClear permits to add non-encrypted client responses
func AddInClear(s []DpClearResponse) []DpClearResponse {
	dataMap := make(map[string][]int64)

	wg := StartParallelize(0)
	for _, elem := range s {
		key := int64ArrayToString(elem.GroupByClear) + " " + int64ArrayToString(elem.GroupByEnc)

		if _, ok := dataMap[key]; ok == false {
			cpy := make([]int64, len(elem.AggregatingAttributes))
			copy(cpy, elem.AggregatingAttributes)
			dataMap[key] = cpy
		} else {
			if PARALLELIZE {
				for i := 0; i < len(dataMap[key]); i = i + VPARALLELIZE {
					wg.Add(1)
					go func(i int) {
						for j := 0; j < VPARALLELIZE && (j+i < len(dataMap[key])); j++ {
							dataMap[key][j+i] += elem.AggregatingAttributes[j+i]
						}
						defer wg.Done()
					}(i)
				}
			} else {
				for i := range dataMap[key] {
					dataMap[key][i] += elem.AggregatingAttributes[i]
				}

			}
			EndParallelize(wg)
		}
	}

	result := make([]DpClearResponse, len(dataMap))

	i := 0
	numGroupsClear := 0
	if len(s) > 0 {
		numGroupsClear = len(s[0].GroupByClear)
	}

	for k, v := range dataMap {
		// *2 (to account for the spaces between the numbers)
		result[i] = DpClearResponse{GroupByClear: StringToInt64Array(k[:numGroupsClear*2]), GroupByEnc: StringToInt64Array(k[numGroupsClear*2:]), AggregatingAttributes: v}
		i++
	}

	return result

}

// PushCothorityAggregatedClientResponses handles the collective aggregation locally.
func (s *Store) PushCothorityAggregatedClientResponses(sNew map[GroupingKey]FilteredResponse) {
	for key, value := range sNew {
		s.Mutex.Lock()
		AddInMap(s.GroupedDeterministicClientResponses, key, value)
		s.Mutex.Unlock()
	}
}

// HasNextAggregatedClientResponses verifies that the server has local grouping results (group attributes).
func (s *Store) HasNextAggregatedClientResponses() bool {
	return len(s.GroupedDeterministicClientResponses) > 0
}

var aggregatedGrps []GroupingKey

// PullCothorityAggregatedClientResponses returns the local results of the grouping.
func (s *Store) PullCothorityAggregatedClientResponses(diffPri bool, noise CipherText) []FilteredResponse {
	aggregatedResults := make([]FilteredResponse, len(s.GroupedDeterministicClientResponses))
	aggregatedGrps = make([]GroupingKey, len(s.GroupedDeterministicClientResponses))
	count := 0
	for i, value := range s.GroupedDeterministicClientResponses {
		aggregatedResults[count] = value
		aggregatedGrps[count] = i
		count++
	}

	s.GroupedDeterministicClientResponses = make(map[GroupingKey]FilteredResponse)

	if diffPri == true {
		for _, v := range aggregatedResults {
			for _, aggr := range v.AggregatingAttributes {
				aggr.Add(aggr, noise)
			}
		}
	}

	return aggregatedResults
}

// PushQuerierKeyEncryptedResponses handles the reception of the key switched (for the querier) results.
func (s *Store) PushQuerierKeyEncryptedResponses(keySwitchedResponse []FilteredResponse) {
	s.DeliverableResults = keySwitchedResponse

}

// PullDeliverableResults gets the results.
func (s *Store) PullDeliverableResults() []FilteredResponse {
	results := s.DeliverableResults
	s.DeliverableResults = s.DeliverableResults[:0]
	return results
}

// DisplayResults shows results and is useful for debugging.
func (s *Store) DisplayResults() {
	for _, v := range s.DeliverableResults {
		log.LLvl1("[ ", v.GroupByEnc, ", ", v.GroupByEnc, " ] : ", v.AggregatingAttributes, ")")
	}
}
