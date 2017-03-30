package serviceI2B2

import (
	"github.com/JoaoAndreSa/MedCo/lib"
	"github.com/satori/go.uuid"
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/crypto.v0/random"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/dedis/onet.v1/network"
	"sync"

	"github.com/JoaoAndreSa/MedCo/protocols"
	"github.com/JoaoAndreSa/MedCo/services"
	"github.com/btcsuite/goleveldb/leveldb/errors"
	"github.com/fanliao/go-concurrentMap"
)

const gobFile = "pre_compute_multiplications.gob"

// ServiceName is the registered name for the medco service.
const ServiceName = "MedCoI2b2"

// SurveyID unique ID for each survey.
type SurveyID string

// SurveyDpQuery is used to trigger the creation of a survey
type SurveyDpQuery struct {
	SurveyGenID  SurveyID
	SurveyID     SurveyID
	Roster       onet.Roster
	ClientPubKey abstract.Point
	MapDPs       map[string]int64
	QueryMode    int64
	Proofs       bool
	AppFlag      bool

	// query statement
	Sum       []string
	Count     bool
	Where     []lib.WhereQueryAttribute
	Predicate string
	GroupBy   []string
	DpData    []lib.ProcessResponse

	// message handling
	IntraMessage  bool
	MessageSource *network.ServerIdentity
}

// Survey represents a survey with the corresponding params
type Survey struct {
	*lib.Store
	Query             SurveyDpQuery
	SurveySecretKey   abstract.Scalar
	ShufflePrecompute []lib.CipherVectorScalar

				     // channels
	SurveyChannel       chan int // To wait for the survey to be created before loading data
	IntermediateChannel chan int
	FinalChannel        chan int // To wait for the root server to send all the final results

	IntermediateResults map[ResultID]lib.FilteredResponse
	FirstTime           bool
	FinalResults        map[ResultID]lib.FilteredResponse
	Noise               lib.CipherText
}

// MsgTypes defines the Message Type ID for all the service's intra-messages.
type MsgTypes struct {
	msgSurveyDpQuery            network.MessageTypeID
	msgSurveyResultSharing      network.MessageTypeID
	msgSurveyFinalResultSharing network.MessageTypeID
	msgSurveyGenerated          network.MessageTypeID
}

var msgTypes = MsgTypes{}

func init() {
	onet.RegisterNewService(ServiceName, NewService)

	msgTypes.msgSurveyDpQuery = network.RegisterMessage(&SurveyDpQuery{})
	msgTypes.msgSurveyResultSharing = network.RegisterMessage(&SurveyResultSharing{})
	msgTypes.msgSurveyFinalResultSharing = network.RegisterMessage(&SurveyFinalResultsSharingMessage{})
	msgTypes.msgSurveyGenerated = network.RegisterMessage(&SurveyGenerated{})

	network.RegisterMessage(&ServiceResult{})
}

// ResultID defines the ID to uniquely identify a result (e.g., Server1 Survey2 4, etc.)
type ResultID struct {
	ServerID network.ServerIdentityID
	SurveyID SurveyID
}

// SurveyResultSharing represents a message containing the intermediate results which are shared with the remaining nodes
type SurveyResultSharing struct {
	SurveyGenID SurveyID
	SurveyID    SurveyID
	ServerID    network.ServerIdentityID
	Result      lib.FilteredResponse
}

// SurveyFinalResultsSharing represents a message containing survey ids and responses
type SurveyFinalResultsSharing struct {
	SurveyGenID SurveyID
	Results     map[ResultID]lib.FilteredResponse
}

// SurveyFinalResultsSharingMessage represents a message containing survey ids and responses in a way that we can send it through protobuf
type SurveyFinalResultsSharingMessage struct {
	SurveyGenID SurveyID
	ID          []ResultID
	FR          []lib.FilteredResponse
}

// SurveyGenerated is used to ensure that all servers get the query/survey before starting the DDT protocol
type SurveyGenerated struct {
	SurveyID SurveyID
}

// ServiceResult will contain final results of a survey and be sent to querier.
type ServiceResult struct {
	Results lib.FilteredResponse
}

// Service defines a service in medco with a survey.
type Service struct {
	*onet.ServiceProcessor

	Survey map[SurveyID]Survey
	SurveyTest *concurrent.ConcurrentMap
	Mutex  sync.Mutex
}

// NewService constructor which registers the needed messages.
func NewService(c *onet.Context) onet.Service {
	newMedCoInstance := &Service{
		ServiceProcessor: onet.NewServiceProcessor(c),
		Survey:           make(map[SurveyID]Survey, 0),
		SurveyTest:       concurrent.NewConcurrentMap(),
	}

	if cerr := newMedCoInstance.RegisterHandler(newMedCoInstance.HandleSurveyDpQuery); cerr != nil {
		log.Fatal("Wrong Handler.", cerr)
	}

	if cerr := newMedCoInstance.RegisterHandler(newMedCoInstance.HandleSurveyResultsSharing); cerr != nil {
		log.Fatal("Wrong Handler.", cerr)
	}

	if cerr := newMedCoInstance.RegisterHandler(newMedCoInstance.HandleSurveyFinalResultsSharing); cerr != nil {
		log.Fatal("Wrong Handler.", cerr)
	}

	if cerr := newMedCoInstance.RegisterHandler(newMedCoInstance.HandleSurveyGenerated); cerr != nil {
		log.Fatal("Wrong Handler.", cerr)
	}

	c.RegisterProcessor(newMedCoInstance, msgTypes.msgSurveyGenerated)
	c.RegisterProcessor(newMedCoInstance, msgTypes.msgSurveyDpQuery)
	c.RegisterProcessor(newMedCoInstance, msgTypes.msgSurveyResultSharing)
	c.RegisterProcessor(newMedCoInstance, msgTypes.msgSurveyFinalResultSharing)

	return newMedCoInstance
}

// Process implements the processor interface and is used to recognize messages broadcasted between servers
func (s *Service) Process(msg *network.Envelope) {
	if msg.MsgType.Equal(msgTypes.msgSurveyDpQuery) {
		tmp := (msg.Msg).(*SurveyDpQuery)
		s.HandleSurveyDpQuery(tmp)
	} else if msg.MsgType.Equal(msgTypes.msgSurveyResultSharing) {
		tmp := (msg.Msg).(*SurveyResultSharing)
		s.HandleSurveyResultsSharing(tmp)
	} else if msg.MsgType.Equal(msgTypes.msgSurveyFinalResultSharing) {
		tmp := (msg.Msg).(*SurveyFinalResultsSharingMessage)
		s.HandleSurveyFinalResultsSharing(tmp)
	} else if msg.MsgType.Equal(msgTypes.msgSurveyGenerated) {
		tmp := (msg.Msg).(*SurveyGenerated)
		s.HandleSurveyGenerated(tmp)
	}
}

// Query Handlers
//______________________________________________________________________________________________________________________

// HandleSurveyGenerated handles the message
func (s *Service) HandleSurveyGenerated(recq *SurveyGenerated) (network.Message, onet.ClientError) {
	(s.Survey[recq.SurveyID].SurveyChannel) <- 1
	return nil, nil
}

// HandleSurveyDpQuery handles the reception of a survey creation query by instantiating the corresponding survey and it will directly request the results
func (s *Service) HandleSurveyDpQuery(sdq *SurveyDpQuery) (network.Message, onet.ClientError) {
	log.LLvl1(s.ServerIdentity().String(), " received a Survey Dp Query")

	surveySecret := network.Suite.Scalar().Pick(random.Stream)

	// if this server is the one receiving the query from the client
	if !sdq.IntraMessage {
		sdq.IntraMessage = true
		sdq.MessageSource = s.ServerIdentity()

		newID := SurveyID(uuid.NewV4().String())
		sdq.SurveyID = newID
		log.Lvl1(s.ServerIdentity().String(), " handles this new survey ", sdq.SurveyID, " ", sdq.SurveyGenID)

		(s.Survey[sdq.SurveyID]) = Survey{
			Store:           lib.NewStore(),
			Query:           *sdq,
			SurveySecretKey: surveySecret,

			SurveyChannel: make(chan int, 100),

			IntermediateResults: make(map[ResultID]lib.FilteredResponse),
		}

		log.LLvl1("1.")
	//	var b string
	//	b = (string)(sdq.SurveyID)
		/*s.SurveyTest.Put(b, Survey{
			Store:           lib.NewStore(),
			Query:           *sdq,
			SurveySecretKey: surveySecret,

			SurveyChannel: make(chan int, 100),

			IntermediateResults: make(map[ResultID]lib.FilteredResponse),
		})*/

		//s.SurveyTest.PutAll(s.Survey[sdq.SurveyID])

/*
		log.LLvl1("2.")
		a, _ := s.SurveyTest.Get(b)
		log.LLvl1("3.")



		log.LLvl1("TESTES", len(a.(Survey).IntermediateResults))

*/
		// broadcasts the query
		err := services.SendISMOthers(s.ServiceProcessor, &sdq.Roster, sdq)
		if err != nil {
			log.Error("broadcasting error ", err)
		}

		// waits for all other nodes to receive the query/survey
		counter := len(s.Survey[sdq.SurveyID].Query.Roster.List) - 1
		for counter > 0 {
			counter = counter - (<-s.Survey[sdq.SurveyID].SurveyChannel)
		}

		// skip Unlynx shuffling
		s.Survey[sdq.SurveyID].PushShuffledProcessResponses(sdq.DpData)

		// det tag + filtering
		s.StartServicePartOne(sdq.SurveyID)

		// aggregating
		r1 := s.Survey[sdq.SurveyID].PullCothorityAggregatedFilteredResponses(false, lib.CipherText{})

		// share intermediate results
		err = services.SendISMOthers(s.ServiceProcessor, &sdq.Roster, &SurveyResultSharing{sdq.SurveyGenID, sdq.SurveyID, s.ServerIdentity().ID, r1[0]})
		if err != nil {
			log.Error("broadcasting error ", err)
		}

		// server saves its own result as the answer to a new survey
		if s.Survey[sdq.SurveyGenID].IntermediateResults == nil {
			tmp := s.Survey[sdq.SurveyGenID]
			tmp.IntermediateResults = make(map[ResultID]lib.FilteredResponse)
			tmp.FirstTime = true
			tmp.IntermediateChannel = make(chan int, 100)
			tmp.FinalChannel = make(chan int, 100)
			s.Survey[sdq.SurveyGenID] = tmp
		}
		s.Survey[sdq.SurveyGenID].IntermediateResults[ResultID{ServerID: s.ServerIdentity().ID, SurveyID: sdq.SurveyID}] = r1[0]

		if int64(len(s.Survey[sdq.SurveyGenID].IntermediateResults)) == services.CountDPs(sdq.MapDPs) {
			(s.Survey[sdq.SurveyGenID].IntermediateChannel) <- 1
		}

		<-s.Survey[sdq.SurveyGenID].IntermediateChannel
		log.Lvl1(s.ServerIdentity(), " completed the first part")

		// if the server is the root... FirstTime ensures it only executes this piece of code once (no matter the number of DPs)
		if s.ServerIdentity().ID == sdq.Roster.List[0].ID && s.Survey[sdq.SurveyGenID].FirstTime {
			log.LLvl1(s.ServerIdentity(), " executes part 2")
			lineSize := int(len(sdq.Sum)) + int(len(sdq.Where)) + int(len(sdq.GroupBy)) + 1 // + 1 is for the possible count attribute
			precomputeShuffle := services.PrecomputationWritingForShuffling(sdq.AppFlag, s.ServerIdentity().String(), gobFile, surveySecret, sdq.Roster.Aggregate, lineSize)

			tmp := s.Survey[sdq.SurveyGenID]
			tmp.FirstTime = false
			tmp.Query = s.Survey[sdq.SurveyID].Query
			tmp.Store = s.Survey[sdq.SurveyID].Store
			tmp.ShufflePrecompute = precomputeShuffle
			s.Survey[sdq.SurveyGenID] = tmp

			s.StartServicePartTwo(sdq.SurveyGenID, (sdq.QueryMode==1))

			finalResultsUnformatted := s.Survey[sdq.SurveyGenID].PullDeliverableResults(false, lib.CipherText{})

			finalResults := make(map[ResultID]lib.FilteredResponse)

			counter := 0
			for v := range s.Survey[sdq.SurveyGenID].IntermediateResults {
				finalResults[ResultID{ServerID: v.ServerID, SurveyID: v.SurveyID}] = finalResultsUnformatted[counter]
				counter = counter + 1
				if (sdq.QueryMode==1){
					break
				}
			}

			// convert the the map to two different arrays (basically serialize the object)
			msg := &(SurveyFinalResultsSharingMessage{})
			msg.SurveyGenID = sdq.SurveyGenID

			msg.ID = make([]ResultID, 0)
			msg.FR = make([]lib.FilteredResponse, 0)

			for k, v := range finalResults {
				msg.ID = append(msg.ID, k)
				msg.FR = append(msg.FR, v)
			}

			// broadcasts the final result
			err = services.SendISMOthers(s.ServiceProcessor, &sdq.Roster, msg)
			if err != nil {
				log.Error("broadcasting error ", err)
			}

			tmp = s.Survey[sdq.SurveyGenID]
			tmp.FinalResults = finalResults
			s.Survey[sdq.SurveyGenID] = tmp

			for i := int64(0); i < sdq.MapDPs[s.ServerIdentity().String()]; i++ {
				(s.Survey[sdq.SurveyGenID].FinalChannel) <- 1
			}
		}

		<-s.Survey[sdq.SurveyGenID].FinalChannel

		if (sdq.QueryMode==1) {
			for _,v := range s.Survey[sdq.SurveyGenID].FinalResults{
				return &ServiceResult{Results: v}, nil
			}
		}

		ret := &ServiceResult{Results: s.Survey[sdq.SurveyGenID].FinalResults[ResultID{ServerID: s.ServerIdentity().ID, SurveyID: sdq.SurveyID}]}
		return ret, nil

	}

	// if it is an intra message (message between the servers)

	(s.Survey[sdq.SurveyID]) = Survey{
		Store:           lib.NewStore(),
		Query:           *sdq,
		SurveySecretKey: surveySecret,

		IntermediateResults: make(map[ResultID]lib.FilteredResponse, 0),
	}

	// sends a signal to unlock waiting channel
	err := s.SendRaw(sdq.MessageSource, &SurveyGenerated{SurveyID: sdq.SurveyID})
	if err != nil {
		log.Error("sending error ", err)
	}

	return &ServiceResult{}, nil
}

// HandleSurveyResultsSharing handles reception of initial results in i2b2 query case
func (s *Service) HandleSurveyResultsSharing(resp *SurveyResultSharing) (network.Message, onet.ClientError) {

	lineSize := int(len(sdq.Sum)) + int(len(sdq.Where)) + int(len(sdq.GroupBy)) + 1 // + 1 is for the possible count attribute
	precomputeShuffle := services.PrecomputationWritingForShuffling(sdq.AppFlag, s.ServerIdentity().String(), gobFile, surveySecret, sdq.Roster.Aggregate, lineSize)

	if s.Survey[resp.SurveyGenID].IntermediateResults == nil {
		tmp := s.Survey[resp.SurveyGenID]
		tmp.IntermediateResults = make(map[ResultID]lib.FilteredResponse)
		tmp.FirstTime = true
		tmp.IntermediateChannel = make(chan int, 100)
		tmp.FinalChannel = make(chan int, 100)
		s.Survey[resp.SurveyGenID] = tmp
	}
	s.Survey[resp.SurveyGenID].IntermediateResults[ResultID{ServerID: resp.ServerID, SurveyID: resp.SurveyID}] = resp.Result


	log.LLvl1(s.ServerIdentity(), " gets a survey response for ", resp.SurveyGenID, " from ", resp.ServerID)
	log.LLvl1(s.ServerIdentity(), " now has ", len(s.Survey[resp.SurveyGenID].IntermediateResults), " surveys with response(s)")

	//if it is the last survey result needed then unblock the channel
	if int64(len(s.Survey[resp.SurveyGenID].IntermediateResults)) == 3 {
		(s.Survey[resp.SurveyGenID].IntermediateChannel) <- 1
	}

	return &ServiceResult{}, nil
}

// HandleSurveyFinalResultsSharing handles reception of final shuffled results in i2b2 query case
func (s *Service) HandleSurveyFinalResultsSharing(respArr *SurveyFinalResultsSharingMessage) (network.Message, onet.ClientError) {
	// convert the message from the double array to a map
	resp := (&SurveyFinalResultsSharing{})
	resp.SurveyGenID = respArr.SurveyGenID

	resp.Results = make(map[ResultID]lib.FilteredResponse)

	for i := 0; i < len(respArr.ID); i++ {
		resp.Results[respArr.ID[i]] = respArr.FR[i]
	}

	// this is received only once and then the channel is unblocked to proceed to last step
	log.LLvl1(s.ServerIdentity(), " gets a final survey response for from ", s.ServerIdentity().String())

	tmp := s.Survey[resp.SurveyGenID]
	tmp.FinalResults = resp.Results
	s.Survey[resp.SurveyGenID] = tmp

	// count the number of responses associated with the server or in other words the number of DPs (to unlock the FinalChannel)
	for k := range tmp.IntermediateResults{
		if k.ServerID == s.ServerIdentity().ID{
			(s.Survey[resp.SurveyGenID].FinalChannel) <- 1
		}
	}

	return &ServiceResult{}, nil
}

// Protocol Handlers
//______________________________________________________________________________________________________________________

// NewProtocol creates a protocol instance executed by all nodes
func (s *Service) NewProtocol(tn *onet.TreeNodeInstance, conf *onet.GenericConfig) (onet.ProtocolInstance, error) {
	tn.SetConfig(conf)

	var pi onet.ProtocolInstance
	var err error

	target := SurveyID(string(conf.Data))

	switch tn.ProtocolName() {
	case protocols.ShufflingProtocolName:
		pi, err = protocols.NewShufflingProtocol(tn)
		if err != nil {
			return nil, err
		}
		shuffle := pi.(*protocols.ShufflingProtocol)

		shuffle.Proofs = s.Survey[target].Query.Proofs
		shuffle.Precomputed = s.Survey[target].ShufflePrecompute
		if tn.IsRoot() {
			targetShuffle := []lib.ProcessResponse{}
			for _, v := range s.Survey[target].IntermediateResults {
				newProcessResponse := lib.ProcessResponse{GroupByEnc: v.GroupByEnc, AggregatingAttributes: v.AggregatingAttributes}
				targetShuffle = append(targetShuffle, newProcessResponse)
			}
			shuffle.TargetOfShuffle = &targetShuffle
		}

	case protocols.DeterministicTaggingProtocolName:
		pi, err = protocols.NewDeterministicTaggingProtocol(tn)
		if err != nil {
			return nil, err
		}
		hashCreation := pi.(*protocols.DeterministicTaggingProtocol)

		aux := s.Survey[target].SurveySecretKey
		hashCreation.SurveySecretKey = &aux
		hashCreation.Proofs = s.Survey[target].Query.Proofs
		hashCreation.NbrQueryAttributes = len(s.Survey[target].Query.Where)
		if tn.IsRoot() {
			shuffledClientResponses := s.Survey[target].PullShuffledProcessResponses()
			queryWhereToTag := []lib.ProcessResponse{}
			for _, v := range s.Survey[target].Query.Where {
				tmp := lib.CipherVector{v.Value}
				queryWhereToTag = append(queryWhereToTag, lib.ProcessResponse{WhereEnc: tmp, GroupByEnc: nil, AggregatingAttributes: nil})
			}
			shuffledClientResponses = append(queryWhereToTag, shuffledClientResponses...)
			hashCreation.TargetOfSwitch = &shuffledClientResponses

		}
	case protocols.DROProtocolName:
		pi, err := protocols.NewShufflingProtocol(tn)
		if err != nil {
			return nil, err
		}

		shuffle := pi.(*protocols.ShufflingProtocol)
		shuffle.Proofs = true
		shuffle.Precomputed = s.Survey[target].ShufflePrecompute

		if tn.IsRoot() {
			clientResponses := make([]lib.ProcessResponse, 0)
			noiseArray := lib.GenerateNoiseValues(1000, 0, 1, 0.1)
			for _, v := range noiseArray {
				clientResponses = append(clientResponses, lib.ProcessResponse{GroupByEnc: nil, AggregatingAttributes: *lib.EncryptIntVector(tn.Roster().Aggregate, []int64{int64(v)})})
			}
			shuffle.TargetOfShuffle = &clientResponses
		}
		return pi, nil

	case protocols.KeySwitchingProtocolName:
		pi, err = protocols.NewKeySwitchingProtocol(tn)
		if err != nil {
			return nil, err
		}

		keySwitch := pi.(*protocols.KeySwitchingProtocol)
		keySwitch.Proofs = s.Survey[target].Query.Proofs
		if tn.IsRoot() {
			coaggr := []lib.FilteredResponse{}

			if lib.DIFFPRI == true {
				coaggr = s.Survey[target].PullDeliverableResults(true, s.Survey[target].Noise)
			} else {
				coaggr = s.Survey[target].PullDeliverableResults(false, lib.CipherText{})
			}

			keySwitch.TargetOfSwitch = &coaggr
			tmp := s.Survey[target].Query.ClientPubKey
			keySwitch.TargetPublicKey = &tmp
		}
	default:
		return nil, errors.New("Service attempts to start an unknown protocol: " + tn.ProtocolName() + ".")
	}
	return pi, nil
}

// StartProtocol starts a specific protocol (Pipeline, Shuffling, etc.)
func (s *Service) StartProtocol(name string, targetSurvey SurveyID) (onet.ProtocolInstance, error) {
	tmp := s.Survey[targetSurvey]
	tree := tmp.Query.Roster.GenerateNaryTreeWithRoot(2, s.ServerIdentity())

	var tn *onet.TreeNodeInstance
	tn = s.NewTreeNodeInstance(tree, tree.Root, name)

	s.Survey[targetSurvey] = tmp
	conf := onet.GenericConfig{Data: []byte(string(targetSurvey))}

	pi, err := s.NewProtocol(tn, &conf)

	s.RegisterProtocolInstance(pi)
	go pi.Dispatch()
	go pi.Start()

	return pi, err
}

// Service Phases
//______________________________________________________________________________________________________________________

// StartServicePartOne starts the first part of the service (with all its different steps/protocols)
func (s *Service) StartServicePartOne(targetSurvey SurveyID) error {

	log.LLvl1(s.ServerIdentity(), " starts a Medco Protocol for survey ", targetSurvey)

	// Tagging Phase
	start := lib.StartTimer(s.ServerIdentity().String() + "_TaggingPhase")

	err := s.TaggingPhase(s.Survey[targetSurvey].Query.SurveyID)
	if err != nil {
		log.Fatal("Error in the Tagging Phase")
	}

	lib.EndTimer(start)

	// Skip Collective Aggregation
	s.Survey[targetSurvey].PushCothorityAggregatedFilteredResponses(s.Survey[targetSurvey].PullLocallyAggregatedResponses())

	return nil
}

// StartServicePartTwo starts the second part of the service (with all its different steps/protocols)
func (s *Service) StartServicePartTwo(targetSurvey SurveyID, aggr bool) error {

	log.LLvl1(s.ServerIdentity(), " starts a Medco Protocol for survey ", targetSurvey)

	// Tagging Phase
	start := lib.StartTimer(s.ServerIdentity().String() + "_TaggingPhase")

	if !aggr {
		err := s.ShufflingPhase(targetSurvey)
		if err != nil {
			log.Fatal("Error in the Tagging Phase")
		}
	} else {
		aggrResponses := []lib.ProcessResponse{}
		for i, v := range s.Survey[targetSurvey].IntermediateResults {
			newProcessResponse := lib.ProcessResponse{GroupByEnc: v.GroupByEnc, AggregatingAttributes: v.AggregatingAttributes}
			for j, w := range s.Survey[targetSurvey].IntermediateResults {
				if j != i {
					cv := lib.NewCipherVector(len(newProcessResponse.AggregatingAttributes))
					cv.Add(newProcessResponse.AggregatingAttributes, w.AggregatingAttributes)
					if s.Survey[targetSurvey].Query.Proofs == true {
						proof := lib.PublishedSimpleAdditionProof{newProcessResponse.AggregatingAttributes, w.AggregatingAttributes, *cv}
						_=proof
					}
					newProcessResponse.AggregatingAttributes = *cv
				}

			}
			aggrResponses = append(aggrResponses, newProcessResponse)
			break
		}
		s.Survey[targetSurvey].PushShuffledProcessResponses(aggrResponses)
	}
	//TODO put it in the new Protocol for survey


	lib.EndTimer(start)

	//skip collective aggregation
	shuffledFinalResponsesUnformat := s.Survey[targetSurvey].PullShuffledProcessResponses()

	shuffledFinalResponsesFormat := make([]lib.FilteredResponse, len(shuffledFinalResponsesUnformat))
	for i, v := range shuffledFinalResponsesUnformat {
		shuffledFinalResponsesFormat[i].GroupByEnc = v.GroupByEnc
		shuffledFinalResponsesFormat[i].AggregatingAttributes = v.AggregatingAttributes
	}

	// here we use the table to store the responses used in key switching
	s.Survey[targetSurvey].PushQuerierKeyEncryptedResponses(shuffledFinalResponsesFormat)

	// DRO Phase
	if lib.DIFFPRI == true {
		start := lib.StartTimer(s.ServerIdentity().String() + "_DROPhase")

		s.DROPhase(s.Survey[targetSurvey].Query.SurveyID)

		lib.EndTimer(start)
	}

	err := s.KeySwitchingPhase(s.Survey[targetSurvey].Query.SurveyID)

	if err != nil {
		log.Fatal("Error in the Tagging Phase")
	}

	return nil
}

// ShufflingPhase performs the shuffling of the ClientResponses
func (s *Service) ShufflingPhase(targetSurvey SurveyID) error {
	pi, err := s.StartProtocol(protocols.ShufflingProtocolName, targetSurvey)
	if err != nil {
		return err
	}
	shufflingResult := <-pi.(*protocols.ShufflingProtocol).FeedbackChannel

	s.Survey[targetSurvey].PushShuffledProcessResponses(shufflingResult)
	return err
}

// TaggingPhase performs the private grouping on the currently collected data.
func (s *Service) TaggingPhase(targetSurvey SurveyID) error {
	if len(s.Survey[targetSurvey].ShuffledProcessResponses) == 0 {
		log.LLvl1(s.ServerIdentity(), "  for survey ", s.Survey[targetSurvey].Query.SurveyID, " has no data to det tag")
		return nil
	}

	pi, err := s.StartProtocol(protocols.DeterministicTaggingProtocolName, targetSurvey)
	if err != nil {
		return err
	}

	deterministicTaggingResult := <-pi.(*protocols.DeterministicTaggingProtocol).FeedbackChannel

	queryWhereTag := []lib.WhereQueryAttributeTagged{}
	for i, v := range deterministicTaggingResult[:len(s.Survey[targetSurvey].Query.Where)] {
		newElem := lib.WhereQueryAttributeTagged{Name: s.Survey[targetSurvey].Query.Where[i].Name, Value: v.DetTagWhere[0]}
		queryWhereTag = append(queryWhereTag, newElem)
	}
	deterministicTaggingResult = deterministicTaggingResult[len(s.Survey[targetSurvey].Query.Where):]
	filteredResponses := services.FilterResponses(s.Survey[targetSurvey].Query.Predicate, queryWhereTag, deterministicTaggingResult)
	s.Survey[targetSurvey].PushDeterministicFilteredResponses(filteredResponses, s.ServerIdentity().String(), s.Survey[targetSurvey].Query.Proofs)
	return err
}

// DROPhase shuffles the list of noise values.
func (s *Service) DROPhase(targetSurvey SurveyID) error {
	tmp := s.Survey[targetSurvey]

	pi, err := s.StartProtocol(protocols.DROProtocolName, targetSurvey)
	if err != nil {
		return err
	}

	shufflingResult := <-pi.(*protocols.ShufflingProtocol).FeedbackChannel

	tmp.Noise = shufflingResult[0].AggregatingAttributes[0]
	s.Survey[targetSurvey] = tmp
	return nil
}

// KeySwitchingPhase performs the switch to the querier's key on the currently aggregated data.
func (s *Service) KeySwitchingPhase(targetSurvey SurveyID) error {
	pi, err := s.StartProtocol(protocols.KeySwitchingProtocolName, targetSurvey)
	if err != nil {
		return err
	}
	keySwitchedAggregatedResponses := <-pi.(*protocols.KeySwitchingProtocol).FeedbackChannel
	s.Survey[targetSurvey].PushQuerierKeyEncryptedResponses(keySwitchedAggregatedResponses)
	return err
}
