package lib

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"gopkg.in/dedis/onet.v1/log"
)

// Store contains all the elements of a survey, it consists of the data structure that each cothority has to
// maintain locally to perform a collective survey.
type Store struct {
	DpResponses                           []ProcessResponse
	DeliverableResults                    []FilteredResponse
	ShuffledProcessResponses              []ProcessResponse

	DpResponsesAggr                       map[GroupingKeyTuple]ProcessResponse
	// LocGroupingAggregating contains the results of the local aggregation.
	LocAggregatedProcessResponse          map[GroupingKey]FilteredResponse

	Mutex                                 sync.Mutex

	// GroupedDeterministicGroupingAttributes & GroupedAggregatingAttributes contain results of the grouping
	// before they are key switched and combined in the last step (key switching).
	GroupedDeterministicFilteredResponses map[GroupingKey]FilteredResponse

	lastID                                uint64
}

type GroupingKeyTuple struct {
	gkt1 GroupingKey
	gkt2 GroupingKey
}

// NewStore is the store constructor.
func NewStore() *Store {
	return &Store{
		DpResponsesAggr:                     make(map[GroupingKeyTuple]ProcessResponse),
		LocAggregatedProcessResponse:         make(map[GroupingKey]FilteredResponse),
		GroupedDeterministicFilteredResponses: make(map[GroupingKey]FilteredResponse),
	}
}

// InsertDPResponse handles the local storage of a new DP response in aggregation or grouping cases.
func (s *Store) InsertDpResponse(cr DpResponse, proofs bool, scq SurveyCreationQuery) {
	grpAttrOrder := scq.GroupBy
	whereAttrOrder := scq.Where
	aggrAttrOrder := scq.Sum

	newResp := ProcessResponse{}
	clearGrp := []int64{}
	clearWhr := []int64{}
	for _,v := range grpAttrOrder{
		log.LLvl1(v)
		log.LLvl1(cr.GroupByClear)
		grp, ok := cr.GroupByClear[v]
		if ok {
			if cr.WhereEnc == nil || cr.GroupByEnc == nil {
				clearGrp = append(clearGrp, grp)
			} else {
				newResp.GroupByEnc = append(newResp.GroupByEnc, IntToCiphertext(grp))
			}
		} else if  grp1, ok := cr.GroupByEnc[v]; ok {
			newResp.GroupByEnc = append(newResp.GroupByEnc, grp1)
		} else {
			log.LLvl1("WRONG attributes 1")
		}
	}
	for _,v := range whereAttrOrder{
		grp, ok := cr.WhereClear[v.Name]
		if ok {
			if cr.WhereEnc == nil || cr.GroupByEnc == nil {
				clearWhr = append(clearWhr, grp)
			} else {
				newResp.WhereEnc = append(newResp.WhereEnc, IntToCiphertext(grp))
			}
		} else if  grp1, ok := cr.WhereEnc[v.Name]; ok {
			newResp.WhereEnc = append(newResp.WhereEnc, grp1)
		} else {
			log.LLvl1("WRONG attributes 2")
		}
	}
	for _,v := range aggrAttrOrder{
		grp  := cr.AggregatingAttributes[v]
		newResp.AggregatingAttributes = append(newResp.AggregatingAttributes, grp)
	}

	if cr.WhereEnc != nil || cr.GroupByEnc != nil {
		s.DpResponses = append(s.DpResponses, newResp)

	} else {
		log.LLvl1("YOUHOU AMIGO")
		value, ok := s.DpResponsesAggr[GroupingKeyTuple{Key(clearGrp), Key(clearWhr)}]
		if ok {
			tmp := *NewCipherVector(len(value.AggregatingAttributes)).Add(value.AggregatingAttributes, newResp.AggregatingAttributes)
			mapValue := s.DpResponsesAggr[GroupingKeyTuple{Key(clearGrp), Key(clearWhr)}]
			mapValue.AggregatingAttributes = tmp
			if mapValue.GroupByEnc == nil {
				mapValue.GroupByEnc = IntArrayToCipherVector(clearGrp)
			}
			if mapValue.WhereEnc == nil {
				mapValue.GroupByEnc = IntArrayToCipherVector(clearWhr)
			}
			s.DpResponsesAggr[GroupingKeyTuple{Key(clearGrp), Key(clearWhr)}] = mapValue

			if proofs {
				publishedAggregationProof := PublishedSimpleAdditionProof{value.AggregatingAttributes, newResp.AggregatingAttributes, mapValue.AggregatingAttributes}
				_=publishedAggregationProof//publication
			}

		} else {
			s.DpResponsesAggr[GroupingKeyTuple{Key(clearGrp), Key(clearWhr)}] = ProcessResponse{GroupByEnc:IntArrayToCipherVector(clearGrp), WhereEnc:IntArrayToCipherVector(clearWhr), AggregatingAttributes:newResp.AggregatingAttributes}
		}
	}

}

// HasNextDpResponse permits to verify if there are new DP responses to be processed.
func (s *Store) HasNextDpResponse() bool {
	return len(s.DpResponses) > 0
}

// PullDpResponses permits to get the received DP responses
func (s *Store) PullDpResponses() []ProcessResponse {
	result := []ProcessResponse{}
	if len(s.DpResponses) > 0 {
		result = s.DpResponses
	} else {
		for _, v := range s.DpResponsesAggr {
			log.LLvl1("PULLDPRESPONSE")
			//newResp := ProcessResponse{}
			//newResp.GroupByEnc = append(IntArrayToCipherVector(v.GroupByEnc))
			//newResp.WhereEnc = append(IntArrayToCipherVector(v.WhereClear), v.WhereEnc...)
			//newResp.AggregatingAttributes = v.AggregatingAttributes
			result = append(result, v)
		}
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

// AddInClear permits to add non-encrypted DP responses
func AddInClear(s []DpClearResponse) []DpClearResponse {
	/*dataMap := make(map[string][]int64)

	wg := StartParallelize(0)
	for _, elem := range s {
		key := int64ArrayToString(elem.GroupByClear) + " " + int64ArrayToString(elem.GroupByEnc) + " " + int64ArrayToString(elem.WhereClear) + " " + int64ArrayToString(elem.WhereEnc)

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
	numGroupsEnc := 0
	numWhereClear := 0
	if len(s) > 0 {
		numGroupsClear = len(s[0].GroupByClear)
		numGroupsEnc = len(s[0].GroupByEnc)
		numWhereClear = len(s[0].WhereClear)
	}

	for k, v := range dataMap {
		// *2 (to account for the spaces between the numbers)
		result[i] = DpClearResponse{GroupByClear: StringToInt64Array(k[:numGroupsClear*2]), GroupByEnc: StringToInt64Array(k[numGroupsClear*2:numGroupsClear*2+numGroupsEnc*2]), WhereClear:StringToInt64Array(k[numGroupsClear*2+numGroupsEnc*2:numGroupsClear*2+numGroupsEnc*2+numWhereClear*2]), WhereEnc:StringToInt64Array(k[numGroupsClear*2+numGroupsEnc*2+numWhereClear*2:]), AggregatingAttributes: v}
		i++
	}

	return result*/
	return nil

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

var aggregatedGrps []GroupingKey

// PullCothorityAggregatedFilteredResponses returns the local results of the grouping.
func (s *Store) PullCothorityAggregatedFilteredResponses(diffPri bool, noise CipherText) []FilteredResponse {
	aggregatedResults := make([]FilteredResponse, len(s.GroupedDeterministicFilteredResponses))
	aggregatedGrps = make([]GroupingKey, len(s.GroupedDeterministicFilteredResponses))
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
func (s *Store) PullDeliverableResults() []FilteredResponse {
	results := s.DeliverableResults
	s.DeliverableResults = s.DeliverableResults[:0]
	return results
}

// DisplayResults shows results and is useful for debugging.
func (s *Store) DisplayResults() {
	for _, v := range s.DeliverableResults {
		log.LLvl1("[ ", v.GroupByEnc, " ] : ", v.AggregatingAttributes, ")")
	}
}
