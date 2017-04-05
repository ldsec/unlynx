package lib

import (
	"fmt"
	"gopkg.in/dedis/onet.v1/log"
	"strconv"
	"strings"
	"sync"
)

// Store contains all the elements of a survey, it consists of the data structure that each cothority has to
// maintain locally to perform a collective survey.
type Store struct {
	DpResponses              []ProcessResponse
	DeliverableResults       []FilteredResponse
	ShuffledProcessResponses []ProcessResponse

	DpResponsesAggr map[GroupingKeyTuple]ProcessResponse
	// LocGroupingAggregating contains the results of the local aggregation.
	LocAggregatedProcessResponse map[GroupingKey]FilteredResponse

	Mutex sync.Mutex

	// GroupedDeterministicGroupingAttributes & GroupedAggregatingAttributes contain results of the grouping
	// before they are key switched and combined in the last step (key switching).
	GroupedDeterministicFilteredResponses map[GroupingKey]FilteredResponse

	lastID uint64
}

// GroupingKeyTuple contains two grouping key
type GroupingKeyTuple struct {
	gkt1 GroupingKey
	gkt2 GroupingKey
}

// NewStore is the store constructor.
func NewStore() *Store {
	return &Store{
		DpResponsesAggr:                       make(map[GroupingKeyTuple]ProcessResponse),
		LocAggregatedProcessResponse:          make(map[GroupingKey]FilteredResponse),
		GroupedDeterministicFilteredResponses: make(map[GroupingKey]FilteredResponse),
	}
}

// proccessParameters converts the sum, where and group by data to a collection of CipherTexts (CipherVector)
func proccessParameters(data []string, clear map[string]int64, encrypted map[string]CipherText, noEnc bool) ([]int64, CipherVector) {
	containerClear := []int64{}
	containerEnc := CipherVector{}

	for _, v := range data {
		// all where and group by attributes are in clear
		if noEnc {
			containerClear = append(containerClear, clear[v])
		} else if !noEnc {
			if value, ok := encrypted[v]; ok {
				containerEnc = append(containerEnc, value)
			} else {
				containerEnc = append(containerEnc, IntToCipherText(clear[v]))
			}
		}
	}
	return containerClear, containerEnc
}

// InsertDpResponse handles the local storage of a new DP response in aggregation or grouping cases.
func (s *Store) InsertDpResponse(cr DpResponse, proofs bool, groupBy, sum []string, where []WhereQueryAttribute) {
	newResp := ProcessResponse{}
	clearGrp := []int64{}
	clearWhr := []int64{}

	noEnc := (cr.WhereEnc == nil && cr.GroupByEnc == nil)
	clearGrp, newResp.GroupByEnc = proccessParameters(groupBy, cr.GroupByClear, cr.GroupByEnc, noEnc)

	whereStrings := make([]string, len(where))
	for i, v := range where {
		whereStrings[i] = v.Name
	}
	clearWhr, newResp.WhereEnc = proccessParameters(whereStrings, cr.WhereClear, cr.WhereEnc, noEnc)
	_, newResp.AggregatingAttributes = proccessParameters(sum, cr.AggregatingAttributesClear, cr.AggregatingAttributesEnc, false)

	if !noEnc {
		s.DpResponses = append(s.DpResponses, newResp)
	} else {
		value, ok := s.DpResponsesAggr[GroupingKeyTuple{Key(clearGrp), Key(clearWhr)}]
		if ok {
			tmp := NewCipherVector(len(value.AggregatingAttributes))
			tmp.Add(value.AggregatingAttributes, newResp.AggregatingAttributes)
			mapValue := s.DpResponsesAggr[GroupingKeyTuple{Key(clearGrp), Key(clearWhr)}]
			mapValue.AggregatingAttributes = *tmp
			s.DpResponsesAggr[GroupingKeyTuple{Key(clearGrp), Key(clearWhr)}] = mapValue

			if proofs {
				publishedAggregationProof := PublishedSimpleAdditionProof{value.AggregatingAttributes, newResp.AggregatingAttributes, mapValue.AggregatingAttributes}
				_ = publishedAggregationProof
			}

		} else {
			s.DpResponsesAggr[GroupingKeyTuple{Key(clearGrp), Key(clearWhr)}] = ProcessResponse{GroupByEnc: IntArrayToCipherVector(clearGrp), WhereEnc: IntArrayToCipherVector(clearWhr), AggregatingAttributes: newResp.AggregatingAttributes}
		}

	}

}

// HasNextDpResponse permits to verify if there are new DP responses to be processed.
func (s *Store) HasNextDpResponse() bool {
	return len(s.DpResponses) > 0
}

// PullDpResponses permits to get the received DP responses
func (s *Store) PullDpResponses() []ProcessResponse {
	result := s.DpResponses
	for _, v := range s.DpResponsesAggr {
		result = append(result, v)
	}
	s.DpResponses = s.DpResponses[:0] //clear table
	return result
}

// PushShuffledProcessResponses stores shuffled responses
func (s *Store) PushShuffledProcessResponses(newShuffledProcessResponses []ProcessResponse) {
	s.ShuffledProcessResponses = append(s.ShuffledProcessResponses, newShuffledProcessResponses...)
}

// PullShuffledProcessResponses gets shuffled process responses
func (s *Store) PullShuffledProcessResponses() []ProcessResponse {
	result := s.ShuffledProcessResponses
	s.ShuffledProcessResponses = s.ShuffledProcessResponses[:0] //clear table
	return result
}

// PushDeterministicFilteredResponses permits to store results of deterministic tagging
func (s *Store) PushDeterministicFilteredResponses(detFilteredResponses []FilteredResponseDet, serverName string, proofs bool) {

	round := StartTimer(serverName + "_ServerLocalAggregation")

	for _, v := range detFilteredResponses {
		s.Mutex.Lock()
		AddInMap(s.LocAggregatedProcessResponse, v.DetTagGroupBy, v.Fr)
		s.Mutex.Unlock()
	}
	if proofs {
		PublishedAggregationProof := AggregationProofCreation(detFilteredResponses, s.LocAggregatedProcessResponse)
		//publication
		_ = PublishedAggregationProof
	}

	EndTimer(round)
}

// HasNextAggregatedResponse verifies the presence of locally aggregated results.
func (s *Store) HasNextAggregatedResponse() bool {
	return len(s.LocAggregatedProcessResponse) > 0
}

// PullLocallyAggregatedResponses permits to get the result of the collective and grouped aggregation
func (s *Store) PullLocallyAggregatedResponses() map[GroupingKey]FilteredResponse {
	LocGroupingAggregatingReturn := s.LocAggregatedProcessResponse
	s.LocAggregatedProcessResponse = make(map[GroupingKey]FilteredResponse)
	return LocGroupingAggregatingReturn

}

func (s *Store) nextID() TempID {
	s.lastID++
	return TempID(s.lastID)
}

// AddInMap permits to add a filtered response with its deterministic tag in a map
func AddInMap(s map[GroupingKey]FilteredResponse, key GroupingKey, added FilteredResponse) {
	if localResult, ok := s[key]; !ok {
		s[key] = added
	} else {
		tmp := NewFilteredResponse(len(added.GroupByEnc), len(added.AggregatingAttributes))
		s[key] = *tmp.Add(localResult, added)
	}
}

// int64ArrayToString transforms an integer array into a string
func int64ArrayToString(s []int64) string {
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

// AddInClear permits to add non-encrypted DP responses
func AddInClear(s []DpClearResponse) []DpClearResponse {
	dataMap := make(map[string][]int64)

	wg := StartParallelize(0)
	for _, elem := range s {
		groupByClear := int64ArrayToString(ConvertMapToData(elem.GroupByClear, "g", 0))
		groupByEnc := int64ArrayToString(ConvertMapToData(elem.GroupByEnc, "g", len(elem.GroupByClear)))
		whereClear := int64ArrayToString(ConvertMapToData(elem.WhereClear, "w", 0))
		whereEnc := int64ArrayToString(ConvertMapToData(elem.WhereEnc, "w", len(elem.WhereClear)))

		//generate a unique tag and use it to aggregate the data
		key := groupByClear + groupByEnc + whereClear + whereEnc
		key = key[:len(key)-1]

		// if the where matches (all 1s) -> filter responses
		if len(elem.WhereClear) > 0 || len(elem.WhereEnc) > 0 {
			if key[len(key)-1:] == "0" {
				//discard these entries
				continue
			}
		}

		cpy := make([]int64, 0)
		cpy = append(cpy, ConvertMapToData(elem.AggregatingAttributesClear, "s", 0)...)
		cpy = append(cpy, ConvertMapToData(elem.AggregatingAttributesEnc, "s", len(elem.AggregatingAttributesClear))...)

		if _, ok := dataMap[key]; ok == false {
			dataMap[key] = cpy
		} else {
			if PARALLELIZE {
				for i := 0; i < len(dataMap[key]); i = i + VPARALLELIZE {
					wg.Add(1)
					go func(i int) {
						for j := 0; j < VPARALLELIZE && (j+i < len(dataMap[key])); j++ {
							dataMap[key][j+i] += cpy[j+i]
						}
						defer wg.Done()
					}(i)
				}
			} else {
				for i := range dataMap[key] {
					dataMap[key][i] += cpy[i]
				}

			}
			EndParallelize(wg)
		}
	}

	result := make([]DpClearResponse, len(dataMap))

	var numGroupsClear, numGroupsEnc, numWhereClear, numWhereEnc, numAggrClear int
	if s != nil && len(s) > 0 {
		numGroupsClear = len(s[0].GroupByClear)
		numGroupsEnc = len(s[0].GroupByEnc)
		numWhereClear = len(s[0].WhereClear)
		numWhereEnc = len(s[0].WhereEnc)
		numAggrClear = len(s[0].AggregatingAttributesClear)
	}

	//it is a pain but we have to convert everything back to a set of maps
	i := 0
	for k, v := range dataMap {
		aux := StringToInt64Array(k)
		result[i] = DpClearResponse{
			GroupByClear:               ConvertDataToMap(aux[:numGroupsClear], "g", 0),
			GroupByEnc:                 ConvertDataToMap(aux[numGroupsClear:numGroupsClear+numGroupsEnc], "g", numGroupsClear),
			WhereClear:                 ConvertDataToMap(aux[numGroupsClear+numGroupsEnc:numGroupsClear+numGroupsEnc+numWhereClear], "w", 0),
			WhereEnc:                   ConvertDataToMap(aux[numGroupsClear+numGroupsEnc+numWhereClear:numGroupsClear+numGroupsEnc+numWhereClear+numWhereEnc], "w", numWhereClear),
			AggregatingAttributesClear: ConvertDataToMap(v[:numAggrClear], "s", 0),
			AggregatingAttributesEnc:   ConvertDataToMap(v[numAggrClear:], "s", numAggrClear),
		}
		i++
	}

	return result
}

// PushCothorityAggregatedFilteredResponses handles the collective aggregation locally.
func (s *Store) PushCothorityAggregatedFilteredResponses(sNew map[GroupingKey]FilteredResponse) {
	for key, value := range sNew {
		s.Mutex.Lock()
		AddInMap(s.GroupedDeterministicFilteredResponses, key, value)
		s.Mutex.Unlock()
	}
}

// HasNextAggregatedFilteredResponses verifies that the server has local grouping results (group attributes).
func (s *Store) HasNextAggregatedFilteredResponses() bool {
	return len(s.GroupedDeterministicFilteredResponses) > 0
}

// PullCothorityAggregatedFilteredResponses returns the local results of the grouping.
func (s *Store) PullCothorityAggregatedFilteredResponses(diffPri bool, noise CipherText) []FilteredResponse {
	aggregatedResults := make([]FilteredResponse, len(s.GroupedDeterministicFilteredResponses))
	aggregatedGrps := make([]GroupingKey, len(s.GroupedDeterministicFilteredResponses))
	count := 0

	for i, value := range s.GroupedDeterministicFilteredResponses {
		aggregatedResults[count] = value
		aggregatedGrps[count] = i
		count++
	}

	s.GroupedDeterministicFilteredResponses = make(map[GroupingKey]FilteredResponse)

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
func (s *Store) PullDeliverableResults(diffPri bool, noise CipherText) []FilteredResponse {
	results := s.DeliverableResults
	s.DeliverableResults = s.DeliverableResults[:0]

	if diffPri == true {
		for _, v := range results {
			for _, aggr := range v.AggregatingAttributes {
				aggr.Add(aggr, noise)
			}
		}
	}

	return results
}

// DisplayResults shows results and is useful for debugging.
func (s *Store) DisplayResults() {
	for _, v := range s.DeliverableResults {
		log.LLvl1("[ ", v.GroupByEnc, " ] : ", v.AggregatingAttributes, ")")
	}
}
