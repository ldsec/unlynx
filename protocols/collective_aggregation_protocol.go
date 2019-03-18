// The collective aggregation protocol collectively aggregates the local results of a query from all the servers.
// It uses a tree structure aggregation:
// 1. the root sends down an aggregation trigger message;
// 2. the leafs respond with their local result;
// 3. parent nodes aggregate the information from their children;
// 4. these nodes forward the aggregation result up the tree.

package protocolsunlynx

import (
	"errors"

	"github.com/lca1/unlynx/lib/store"

	"sync"

	"github.com/lca1/unlynx/lib/aggregation"

	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
	"github.com/dedis/onet/network"
	"github.com/lca1/unlynx/lib"
)

// CollectiveAggregationProtocolName is the registered name for the collective aggregation protocol.
const CollectiveAggregationProtocolName = "CollectiveAggregation"

// EMPTYKEY Const string to use as default key when use SimpleData array
const EMPTYKEY = ""

func init() {
	network.RegisterMessage(DataReferenceMessage{})
	network.RegisterMessage(ChildAggregatedDataMessage{})
	network.RegisterMessage(ChildAggregatedDataBytesMessage{})
	network.RegisterMessage(CADBLengthMessage{})
	if _, err := onet.GlobalProtocolRegister(CollectiveAggregationProtocolName, NewCollectiveAggregationProtocol); err != nil {
		log.Fatal("Error registering <CollectiveAggregationProtocol>:", err)
	}
}

// Messages
//______________________________________________________________________________________________________________________

// CothorityAggregatedData is the collective aggregation result.
type CothorityAggregatedData struct {
	GroupedData map[libunlynx.GroupingKey]libunlynx.FilteredResponse
}

// DataReferenceMessage message sent to trigger an aggregation protocol.
type DataReferenceMessage struct{}

// ChildAggregatedDataMessage contains one node's aggregated data.
type ChildAggregatedDataMessage struct {
	ChildData []libunlynx.FilteredResponseDet
}

// ChildAggregatedDataBytesMessage is ChildAggregatedDataMessage in bytes.
type ChildAggregatedDataBytesMessage struct {
	Data []byte
}

// CADBLengthMessage is a message containing the lengths to read a shuffling message in bytes
type CADBLengthMessage struct {
	GacbLength int
	AabLength  int
	//PgaebLength int
	DtbLength int
}

// Structs
//______________________________________________________________________________________________________________________

type dataReferenceStruct struct {
	*onet.TreeNode
	DataReferenceMessage
}

type childAggregatedDataBytesStruct struct {
	*onet.TreeNode
	ChildAggregatedDataBytesMessage
}

type cadmbLengthStruct struct {
	*onet.TreeNode
	CADBLengthMessage
}

// Protocol
//______________________________________________________________________________________________________________________

// CollectiveAggregationProtocol performs an aggregation of the data held by every node in the cothority.
type CollectiveAggregationProtocol struct {
	*onet.TreeNodeInstance

	// Protocol feedback channel
	FeedbackChannel chan CothorityAggregatedData

	// Protocol communication channels
	DataReferenceChannel chan dataReferenceStruct
	LengthNodeChannel    chan []cadmbLengthStruct
	ChildDataChannel     chan []childAggregatedDataBytesStruct

	// Protocol state data
	GroupedData *map[libunlynx.GroupingKey]libunlynx.FilteredResponse
	SimpleData  *[]libunlynx.CipherText
	Proofs      bool
}

// NewCollectiveAggregationProtocol initializes the protocol instance.
func NewCollectiveAggregationProtocol(n *onet.TreeNodeInstance) (onet.ProtocolInstance, error) {
	pap := &CollectiveAggregationProtocol{
		TreeNodeInstance: n,
		FeedbackChannel:  make(chan CothorityAggregatedData),
	}

	err := pap.RegisterChannel(&pap.DataReferenceChannel)
	if err != nil {
		return nil, errors.New("couldn't register data reference channel: " + err.Error())
	}

	err = pap.RegisterChannel(&pap.ChildDataChannel)
	if err != nil {
		return nil, errors.New("couldn't register child-data channel: " + err.Error())
	}

	if err := pap.RegisterChannel(&pap.LengthNodeChannel); err != nil {
		return nil, errors.New("couldn't register data reference channel: " + err.Error())
	}

	return pap, nil
}

// Start is called at the root to begin the execution of the protocol.
func (p *CollectiveAggregationProtocol) Start() error {
	log.Lvl1(p.ServerIdentity(), " started a Colective Aggregation Protocol")
	if err := p.SendToChildren(&DataReferenceMessage{}); err != nil {
		log.Fatal("Error sending <DataReferenceMessage>:", err)
	}
	return nil
}

// Dispatch is called at each node and handle incoming messages.
func (p *CollectiveAggregationProtocol) Dispatch() error {
	defer p.Done()
	p.checkData()

	// 1. Aggregation announcement phase
	if !p.IsRoot() {
		p.aggregationAnnouncementPhase()
	}

	// 2. Ascending aggregation phase
	aggregatedData := p.ascendingAggregationPhase()
	log.Lvl1(p.ServerIdentity(), " completed aggregation phase (", len(*aggregatedData), "group(s) )")

	// 3. Result reporting
	if p.IsRoot() {
		p.FeedbackChannel <- CothorityAggregatedData{*aggregatedData}
	}
	return nil
}

// Announce forwarding down the tree.
func (p *CollectiveAggregationProtocol) aggregationAnnouncementPhase() {
	dataReferenceMessage := <-p.DataReferenceChannel
	if !p.IsLeaf() {
		if err := p.SendToChildren(&dataReferenceMessage.DataReferenceMessage); err != nil {
			log.Fatal("Error sending <DataReferenceMessage>:", err)
		}
	}
}

// Results pushing up the tree containing aggregation results.
func (p *CollectiveAggregationProtocol) ascendingAggregationPhase() *map[libunlynx.GroupingKey]libunlynx.FilteredResponse {
	roundTotComput := libunlynx.StartTimer(p.Name() + "_CollectiveAggregation(ascendingAggregation)")

	if !p.IsLeaf() {
		length := make([]cadmbLengthStruct, 0)
		for _, v := range <-p.LengthNodeChannel {
			length = append(length, v)
		}
		datas := make([]childAggregatedDataBytesStruct, 0)
		for _, v := range <-p.ChildDataChannel {
			datas = append(datas, v)
		}

		cvMap := make(map[libunlynx.GroupingKey][]libunlynx.CipherVector)

		if p.Proofs {
			for k, v := range *p.GroupedData {
				libunlynxstore.FormatAggregationProofs(libunlynx.FilteredResponseDet{DetTagGroupBy: k, Fr: v}, cvMap)
			}
		}
		for i, v := range length {
			childrenContribution := ChildAggregatedDataMessage{}
			childrenContribution.FromBytes(datas[i].Data, v.GacbLength, v.AabLength, v.DtbLength)

			roundComput := libunlynx.StartTimer(p.Name() + "_CollectiveAggregation(Aggregation)")

			for _, aggr := range childrenContribution.ChildData {
				localAggr, ok := (*p.GroupedData)[aggr.DetTagGroupBy]

				if p.Proofs {
					libunlynxstore.FormatAggregationProofs(aggr, cvMap)
				}

				if ok {
					tmp := libunlynx.NewCipherVector(len(localAggr.AggregatingAttributes))
					tmp.Add(localAggr.AggregatingAttributes, aggr.Fr.AggregatingAttributes)

					localAggr.AggregatingAttributes = *tmp
				} else {
					localAggr = aggr.Fr
				}
				(*p.GroupedData)[aggr.DetTagGroupBy] = localAggr
			}
			libunlynx.EndTimer(roundComput)

			roundProofs := libunlynx.StartTimer(p.Name() + "_CollectiveAggregation(Proof-2ndPart)")

			if p.Proofs {
				for k, v := range cvMap {
					libunlynxaggr.AggregationListProofCreation(v, (*p.GroupedData)[k].AggregatingAttributes)
				}
			}
			libunlynx.EndTimer(roundProofs)
		}
	}

	libunlynx.EndTimer(roundTotComput)

	if !p.IsRoot() {
		detAggrResponses := make([]libunlynx.FilteredResponseDet, len(*p.GroupedData))
		count := 0
		for i, v := range *p.GroupedData {
			detAggrResponses[count].DetTagGroupBy = i
			detAggrResponses[count].Fr = v
			count++
		}

		message := ChildAggregatedDataBytesMessage{}

		var gacbLength, aabLength, dtbLength int

		message.Data, gacbLength, aabLength, dtbLength = (&ChildAggregatedDataMessage{detAggrResponses}).ToBytes()
		childrenContribution := ChildAggregatedDataMessage{}
		childrenContribution.FromBytes(message.Data, gacbLength, aabLength, dtbLength)

		if err := p.SendToParent(&CADBLengthMessage{gacbLength, aabLength, dtbLength}); err != nil {
			log.Fatal("Error sending <CADBLengthMessage>:", err)
		}
		if err := p.SendToParent(&message); err != nil {
			log.Fatal("Error sending <ChildAggregatedDataMessage>:", err)
		}
	}

	return p.GroupedData
}

// Setup and return the data needed in the aggregation to a usable format
func (p *CollectiveAggregationProtocol) checkData() {
	// If no data is passed to the collection protocol
	if p.GroupedData == nil && p.SimpleData == nil {
		log.Fatal("no data reference is provided")
		// If both data entry points are used
	} else if p.GroupedData != nil && p.SimpleData != nil {
		log.Fatal("two data references are given in the struct")
		// If we are using the GroupedData keep everything as is
	} else if p.GroupedData != nil {
		return
		// If we are using the SimpleData struct we must convert it to a GroupedData struct
	} else {
		result := make(map[libunlynx.GroupingKey]libunlynx.FilteredResponse)
		if len(*p.SimpleData) > 0 {
			result[EMPTYKEY] = libunlynx.FilteredResponse{
				AggregatingAttributes: make([]libunlynx.CipherText, len(*p.SimpleData)),
			}
			for i, v := range *p.SimpleData {
				result[EMPTYKEY].AggregatingAttributes[i] = v
			}
		}
		p.GroupedData = &result
		p.SimpleData = nil
	}
}

// Conversion
//______________________________________________________________________________________________________________________

// ToBytes converts a ChildAggregatedDataMessage to a byte array
func (sm *ChildAggregatedDataMessage) ToBytes() ([]byte, int, int, int) {

	b := make([]byte, 0)
	bb := make([][]byte, len((*sm).ChildData))

	var gacbLength int
	var aabLength int
	//var pgaebLength int
	var dtbLength int

	wg := libunlynx.StartParallelize(len((*sm).ChildData))
	var mutexCD sync.Mutex
	for i := range (*sm).ChildData {
		go func(i int) {
			defer wg.Done()

			mutexCD.Lock()
			data := (*sm).ChildData[i]
			mutexCD.Unlock()

			aux, gacbAux, aabAux, dtbAux := data.ToBytes()

			mutexCD.Lock()
			bb[i] = aux
			gacbLength = gacbAux
			aabLength = aabAux
			dtbLength = dtbAux
			mutexCD.Unlock()

		}(i)
	}
	libunlynx.EndParallelize(wg)

	for _, el := range bb {
		b = append(b, el...)
	}
	return b, gacbLength, aabLength, dtbLength
}

// FromBytes converts a byte array to a ChildAggregatedDataMessage. Note that you need to create the (empty) object beforehand.
func (sm *ChildAggregatedDataMessage) FromBytes(data []byte, gacbLength, aabLength, dtbLength int) {
	cipherTextSize := libunlynx.CipherTextByteSize()
	elementLength := gacbLength*cipherTextSize + aabLength*cipherTextSize + dtbLength

	if elementLength != 0 && len(data) > 0 {
		var nbrChildData int
		nbrChildData = len(data) / elementLength

		(*sm).ChildData = make([]libunlynx.FilteredResponseDet, nbrChildData)
		wg := libunlynx.StartParallelize(nbrChildData)
		for i := 0; i < nbrChildData; i++ {
			v := data[i*elementLength : i*elementLength+elementLength]
			go func(v []byte, i int) {
				defer wg.Done()
				(*sm).ChildData[i].FromBytes(v, gacbLength, aabLength, dtbLength)
			}(v, i)
		}
		libunlynx.EndParallelize(wg)
	}
}
