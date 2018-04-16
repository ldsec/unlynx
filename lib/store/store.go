package store

import (
	"github.com/lca1/unlynx/lib"
	"github.com/lca1/unlynx/lib/proofs"
	"github.com/dedis/onet/log"
	"sync"
)

// Store contains all the elements of a survey, it consists of the data structure that each cothority has to
// maintain locally to perform a collective survey.
type Store struct {
	DpResponses              []libunlynx.ProcessResponse
	DeliverableResults       []libunlynx.FilteredResponse
	ShuffledProcessResponses []libunlynx.ProcessResponse

	DpResponsesAggr map[GroupingKeyTuple]libunlynx.ProcessResponse
	// LocGroupingAggregating contains the results of the local aggregation.
	LocAggregatedProcessResponse map[libunlynx.GroupingKey]libunlynx.FilteredResponse

	Mutex sync.Mutex

	// GroupedDeterministicGroupingAttributes & GroupedAggregatingAttributes contain results of the grouping
	// before they are key switched and combined in the last step (key switching).
	GroupedDeterministicFilteredResponses map[libunlynx.GroupingKey]libunlynx.FilteredResponse

	lastID uint64
}

// GroupingKeyTuple contains two grouping key
type GroupingKeyTuple struct {
	gkt1 libunlynx.GroupingKey
	gkt2 libunlynx.GroupingKey
}

// NewStore is the store constructor.
func NewStore() *Store {
	return &Store{
		DpResponsesAggr:                       make(map[GroupingKeyTuple]libunlynx.ProcessResponse),
		LocAggregatedProcessResponse:          make(map[libunlynx.GroupingKey]libunlynx.FilteredResponse),
		GroupedDeterministicFilteredResponses: make(map[libunlynx.GroupingKey]libunlynx.FilteredResponse),
	}
}

// proccessParameters converts the sum, where and group by data to a collection of CipherTexts (CipherVector)
func proccessParameters(data []string, clear map[string]int64, encrypted map[string]libunlynx.CipherText, noEnc bool) ([]int64, libunlynx.CipherVector) {
	containerClear := []int64{}
	containerEnc := libunlynx.CipherVector{}

	for _, v := range data {
		// all where and group by attributes are in clear
		if noEnc {
			containerClear = append(containerClear, clear[v])
		} else if !noEnc {
			if value, ok := encrypted[v]; ok {
				containerEnc = append(containerEnc, value)
			} else {
				containerEnc = append(containerEnc, libunlynx.IntToCipherText(clear[v]))
			}
		}
	}
	return containerClear, containerEnc
}

// InsertDpResponse handles the local storage of a new DP response in aggregation or grouping cases.
func (s *Store) InsertDpResponse(cr libunlynx.DpResponse, proofsB bool, groupBy, sum []string, where []libunlynx.WhereQueryAttribute) {
	newResp := libunlynx.ProcessResponse{}
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
		value, ok := s.DpResponsesAggr[GroupingKeyTuple{libunlynx.Key(clearGrp), libunlynx.Key(clearWhr)}]
		if ok {
			tmp := libunlynx.NewCipherVector(len(value.AggregatingAttributes))
			tmp.Add(value.AggregatingAttributes, newResp.AggregatingAttributes)
			mapValue := s.DpResponsesAggr[GroupingKeyTuple{libunlynx.Key(clearGrp), libunlynx.Key(clearWhr)}]
			mapValue.AggregatingAttributes = *tmp
			s.DpResponsesAggr[GroupingKeyTuple{libunlynx.Key(clearGrp), libunlynx.Key(clearWhr)}] = mapValue

			if proofsB {
				publishedAggregationProof := proofs.PublishedSimpleAdditionProof{value.AggregatingAttributes, newResp.AggregatingAttributes, mapValue.AggregatingAttributes}
				_ = publishedAggregationProof
			}

		} else {
			s.DpResponsesAggr[GroupingKeyTuple{libunlynx.Key(clearGrp),libunlynx.Key(clearWhr)}] = libunlynx.ProcessResponse{GroupByEnc: libunlynx.IntArrayToCipherVector(clearGrp), WhereEnc: libunlynx.IntArrayToCipherVector(clearWhr), AggregatingAttributes: newResp.AggregatingAttributes}
		}

	}

}

// HasNextDpResponse permits to verify if there are new DP responses to be processed.
func (s *Store) HasNextDpResponse() bool {
	return len(s.DpResponses) > 0
}

// PullDpResponses permits to get the received DP responses
func (s *Store) PullDpResponses() []libunlynx.ProcessResponse {
	result := s.DpResponses
	for _, v := range s.DpResponsesAggr {
		result = append(result, v)
	}
	s.DpResponses = s.DpResponses[:0] //clear table
	return result
}

// PushShuffledProcessResponses stores shuffled responses
func (s *Store) PushShuffledProcessResponses(newShuffledProcessResponses []libunlynx.ProcessResponse) {
	s.ShuffledProcessResponses = append(s.ShuffledProcessResponses, newShuffledProcessResponses...)
}

// PullShuffledProcessResponses gets shuffled process responses
func (s *Store) PullShuffledProcessResponses() []libunlynx.ProcessResponse {
	result := s.ShuffledProcessResponses
	s.ShuffledProcessResponses = s.ShuffledProcessResponses[:0] //clear table
	return result
}

// PushDeterministicFilteredResponses permits to store results of deterministic tagging
func (s *Store) PushDeterministicFilteredResponses(detFilteredResponses []libunlynx.FilteredResponseDet, serverName string, proofsB bool) {

	round := libunlynx.StartTimer(serverName + "_ServerLocalAggregation")

	for _, v := range detFilteredResponses {
		s.Mutex.Lock()
		libunlynx.AddInMap(s.LocAggregatedProcessResponse, v.DetTagGroupBy, v.Fr)
		s.Mutex.Unlock()
	}
	if proofsB {
		PublishedAggregationProof := proofs.AggregationProofCreation(detFilteredResponses, s.LocAggregatedProcessResponse)
		//publication
		_ = PublishedAggregationProof
	}

	libunlynx.EndTimer(round)
}

// HasNextAggregatedResponse verifies the presence of locally aggregated results.
func (s *Store) HasNextAggregatedResponse() bool {
	return len(s.LocAggregatedProcessResponse) > 0
}

// PullLocallyAggregatedResponses permits to get the result of the collective and grouped aggregation
func (s *Store) PullLocallyAggregatedResponses() map[libunlynx.GroupingKey]libunlynx.FilteredResponse {
	LocGroupingAggregatingReturn := s.LocAggregatedProcessResponse
	s.LocAggregatedProcessResponse = make(map[libunlynx.GroupingKey]libunlynx.FilteredResponse)
	return LocGroupingAggregatingReturn

}

func (s *Store) nextID() libunlynx.TempID {
	s.lastID++
	return libunlynx.TempID(s.lastID)
}

// AddInClear permits to add non-encrypted DP responses
func AddInClear(s []libunlynx.DpClearResponse) []libunlynx.DpClearResponse {
	dataMap := make(map[string][]int64)

	wg := libunlynx.StartParallelize(0)
	for _, elem := range s {
		groupByClear := libunlynx.Int64ArrayToString(libunlynx.ConvertMapToData(elem.GroupByClear, "g", 0))
		groupByEnc := libunlynx.Int64ArrayToString(libunlynx.ConvertMapToData(elem.GroupByEnc, "g", len(elem.GroupByClear)))
		whereClear := libunlynx.Int64ArrayToString(libunlynx.ConvertMapToData(elem.WhereClear, "w", 0))
		whereEnc := libunlynx.Int64ArrayToString(libunlynx.ConvertMapToData(elem.WhereEnc, "w", len(elem.WhereClear)))

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
		cpy = append(cpy, libunlynx.ConvertMapToData(elem.AggregatingAttributesClear, "s", 0)...)
		cpy = append(cpy, libunlynx.ConvertMapToData(elem.AggregatingAttributesEnc, "s", len(elem.AggregatingAttributesClear))...)

		if _, ok := dataMap[key]; ok == false {
			dataMap[key] = cpy
		} else {
			if libunlynx.PARALLELIZE {
				for i := 0; i < len(dataMap[key]); i = i + libunlynx.VPARALLELIZE {
					wg.Add(1)
					go func(i int) {
						for j := 0; j < libunlynx.VPARALLELIZE && (j+i < len(dataMap[key])); j++ {
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
			libunlynx.EndParallelize(wg)
		}
	}

	result := make([]libunlynx.DpClearResponse, len(dataMap))

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
		aux := libunlynx.StringToInt64Array(k)
		result[i] = libunlynx.DpClearResponse{
			GroupByClear:               libunlynx.ConvertDataToMap(aux[:numGroupsClear], "g", 0),
			GroupByEnc:                 libunlynx.ConvertDataToMap(aux[numGroupsClear:numGroupsClear+numGroupsEnc], "g", numGroupsClear),
			WhereClear:                 libunlynx.ConvertDataToMap(aux[numGroupsClear+numGroupsEnc:numGroupsClear+numGroupsEnc+numWhereClear], "w", 0),
			WhereEnc:                   libunlynx.ConvertDataToMap(aux[numGroupsClear+numGroupsEnc+numWhereClear:numGroupsClear+numGroupsEnc+numWhereClear+numWhereEnc], "w", numWhereClear),
			AggregatingAttributesClear: libunlynx.ConvertDataToMap(v[:numAggrClear], "s", 0),
			AggregatingAttributesEnc:   libunlynx.ConvertDataToMap(v[numAggrClear:], "s", numAggrClear),
		}
		i++
	}

	return result
}

// PushCothorityAggregatedFilteredResponses handles the collective aggregation locally.
func (s *Store) PushCothorityAggregatedFilteredResponses(sNew map[libunlynx.GroupingKey]libunlynx.FilteredResponse) {
	for key, value := range sNew {
		s.Mutex.Lock()
		libunlynx.AddInMap(s.GroupedDeterministicFilteredResponses, key, value)
		s.Mutex.Unlock()
	}
}

// HasNextAggregatedFilteredResponses verifies that the server has local grouping results (group attributes).
func (s *Store) HasNextAggregatedFilteredResponses() bool {
	return len(s.GroupedDeterministicFilteredResponses) > 0
}

// PullCothorityAggregatedFilteredResponses returns the local results of the grouping.
func (s *Store) PullCothorityAggregatedFilteredResponses(diffPri bool, noise libunlynx.CipherText) []libunlynx.FilteredResponse {
	aggregatedResults := make([]libunlynx.FilteredResponse, len(s.GroupedDeterministicFilteredResponses))
	aggregatedGrps := make([]libunlynx.GroupingKey, len(s.GroupedDeterministicFilteredResponses))
	count := 0

	for i, value := range s.GroupedDeterministicFilteredResponses {
		aggregatedResults[count] = value
		aggregatedGrps[count] = i
		count++
	}

	s.GroupedDeterministicFilteredResponses = make(map[libunlynx.GroupingKey]libunlynx.FilteredResponse)

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
func (s *Store) PushQuerierKeyEncryptedResponses(keySwitchedResponse []libunlynx.FilteredResponse) {
	s.DeliverableResults = keySwitchedResponse
}

// PullDeliverableResults gets the results.
func (s *Store) PullDeliverableResults(diffPri bool, noise libunlynx.CipherText) []libunlynx.FilteredResponse {
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
