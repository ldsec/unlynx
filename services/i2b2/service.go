package serviceI2B2

import (
	"github.com/JoaoAndreSa/MedCo/lib"
	"github.com/satori/go.uuid"
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/crypto.v0/random"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/dedis/onet.v1/network"

	"github.com/JoaoAndreSa/MedCo/protocols"
	"github.com/JoaoAndreSa/MedCo/services"
	"github.com/btcsuite/goleveldb/leveldb/errors"
	"github.com/fanliao/go-concurrentMap"
	"os"
	"sync"
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

	SurveyChannel       chan int // To wait for the survey to be created before loading data
	IntermediateChannel chan int
	FinalChannel        chan int // To wait for the root server to send all the final results

	IntermediateResults map[ResultID]lib.FilteredResponse
	FirstTime           bool
	FinalResults        map[ResultID]lib.FilteredResponse
	Noise               lib.CipherText
}

func castToSurvey(object interface{}, err error) Survey {
	if err != nil {
		log.Fatal("Error reading map")
	}
	return object.(Survey)
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
	ID          ResultID
	Result      lib.FilteredResponse
	MapDPs      map[string]int64
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

	Survey *concurrent.ConcurrentMap
	Mutex  *sync.Mutex
}

// NewService constructor which registers the needed messages.
func NewService(c *onet.Context) onet.Service {
	newMedCoInstance := &Service{
		ServiceProcessor: onet.NewServiceProcessor(c),
		Survey:           concurrent.NewConcurrentMap(),
		Mutex:            &sync.Mutex{},
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
	(castToSurvey(s.Survey.Get((string)(recq.SurveyID))).SurveyChannel) <- 1
	return nil, nil
}

// HandleSurveyDpQuery handles the reception of a survey creation query by instantiating the corresponding survey and it will directly request the results
func (s *Service) HandleSurveyDpQuery(sdq *SurveyDpQuery) (network.Message, onet.ClientError) {
	log.LLvl1(s.ServerIdentity().String(), " received a Survey Dp Query")

	surveySecret := network.Suite.Scalar().Pick(random.Stream)

	// if this server is the one receiving the query from the client
	if !sdq.IntraMessage {
		nbrDPsLocal := sdq.MapDPs[s.String()]
		sdq.IntraMessage = true
		sdq.MessageSource = s.ServerIdentity()

		newID := SurveyID(uuid.NewV4().String())
		sdq.SurveyID = newID
		log.Lvl1(s.ServerIdentity().String(), " handles this new survey", sdq.SurveyID, "from the general survey", sdq.SurveyGenID)

		// no need for the remaining channels (only when handling the general survey)
		s.Survey.Put((string)(sdq.SurveyID), Survey{
			Store:           lib.NewStore(),
			Query:           *sdq,
			SurveySecretKey: surveySecret,

			SurveyChannel: make(chan int, 100),

			IntermediateResults: make(map[ResultID]lib.FilteredResponse),
		})

		if _, err := os.Stat(gobFile); os.IsNotExist(err) {
			lineSize := int(len(sdq.Sum)) + int(len(sdq.Where)) + int(len(sdq.GroupBy)) + 1 // + 1 is for the possible count attribute
			services.PrecomputationWritingForShuffling(sdq.AppFlag, gobFile, s.ServerIdentity().String(), surveySecret, sdq.Roster.Aggregate, lineSize)
		}

		// broadcasts the query
		err := services.SendISMOthers(s.ServiceProcessor, &sdq.Roster, sdq)
		if err != nil {
			log.Error("broadcasting error ", err)
		}

		// waits for all other nodes to receive the query/survey
		counter := len(sdq.Roster.List) - 1
		for counter > 0 {
			counter = counter - <-castToSurvey(s.Survey.Get((string)(sdq.SurveyID))).SurveyChannel
		}

		// skip Unlynx shuffling
		survey := castToSurvey(s.Survey.Get((string)(sdq.SurveyID)))
		survey.PushShuffledProcessResponses(sdq.DpData)
		s.Survey.Put(string(sdq.SurveyID), survey)

		// deterministic tag + filter responses
		s.StartServicePartOne(sdq.SurveyID)

		// aggregating responses
		survey = castToSurvey(s.Survey.Get((string)(sdq.SurveyID)))
		r1 := survey.PullCothorityAggregatedFilteredResponses(false, lib.CipherText{})
		s.Survey.Put(string(sdq.SurveyID), survey)

		// share intermediate results
		err = services.SendISMOthers(s.ServiceProcessor, &sdq.Roster, &SurveyResultSharing{sdq.SurveyGenID, ResultID{SurveyID: sdq.SurveyID, ServerID: s.ServerIdentity().ID}, r1[0], sdq.MapDPs})
		if err != nil {
			log.Error("broadcasting error ", err)
		}

		// server saves its own result as the answer to a new general survey
		s.Mutex.Lock() // to ensure that we add a new general survey without concurrency issues
		aux, err := s.Survey.Get((string)(sdq.SurveyGenID))

		if err != nil || aux == nil || aux.(Survey).IntermediateResults == nil {
			survey = Survey{}
			survey.IntermediateResults = make(map[ResultID]lib.FilteredResponse)
			survey.FirstTime = true
			survey.IntermediateChannel = make(chan int, 100)
			survey.FinalChannel = make(chan int, 100)
			survey.ShufflePrecompute = services.ReadPrecomputedFile(gobFile)
		} else {
			survey = aux.(Survey)
		}
		survey.IntermediateResults[ResultID{ServerID: s.ServerIdentity().ID, SurveyID: sdq.SurveyID}] = r1[0]
		log.LLvl1(s.ServerIdentity(), " now has ", len(survey.IntermediateResults), " surveys with response(s)")

		s.Survey.Put((string)(sdq.SurveyGenID), survey)

		survey = castToSurvey(s.Survey.Get((string)(sdq.SurveyGenID)))
		size := len(survey.IntermediateResults)

		if int64(size) == services.CountDPs(sdq.MapDPs) {
			for i:= 0; i< int(nbrDPsLocal); i++ {
				(castToSurvey(s.Survey.Get((string)(sdq.SurveyGenID))).IntermediateChannel) <- 1
			}
		}
		s.Mutex.Unlock()

		<-castToSurvey(s.Survey.Get((string)(sdq.SurveyGenID))).IntermediateChannel

		log.LLvl1(s.ServerIdentity(), " END ROUND 1")

		var localCheck bool = false
		s.Mutex.Lock()
		survey = castToSurvey(s.Survey.Get((string)(sdq.SurveyGenID)))
		if survey.FirstTime {
			survey.FirstTime = false
			localCheck = true
		}
		s.Survey.Put((string)(sdq.SurveyGenID), survey)
		s.Mutex.Unlock()


		// if the server is the root... FirstTime ensures it only executes this piece of code once (no matter the number of DPs)
		if s.ServerIdentity().ID == sdq.Roster.List[0].ID && localCheck {
			aux := castToSurvey(s.Survey.Get((string)(sdq.SurveyID)))
			survey.Query = aux.Query
			survey.Store = aux.Store
			survey.ShufflePrecompute = services.ReadPrecomputedFile(gobFile)

			s.Survey.Put((string)(sdq.SurveyGenID), survey)

			s.StartServicePartTwo(sdq.SurveyGenID, (sdq.QueryMode == 1))

			survey = castToSurvey(s.Survey.Get((string)(sdq.SurveyGenID)))
			finalResultsUnformatted := survey.PullDeliverableResults(false, lib.CipherText{})
			s.Survey.Put((string)(sdq.SurveyGenID), survey)

			finalResults := make(map[ResultID]lib.FilteredResponse)

			counter := 0
			for v := range survey.IntermediateResults {
				finalResults[ResultID{ServerID: v.ServerID, SurveyID: v.SurveyID}] = finalResultsUnformatted[counter]
				counter = counter + 1
				if sdq.QueryMode == 1 {
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

			survey.FinalResults = finalResults
			s.Survey.Put((string)(sdq.SurveyGenID), survey)

			for i := int64(0); i < sdq.MapDPs[s.String()]; i++ {
				(castToSurvey(s.Survey.Get((string)(sdq.SurveyGenID))).FinalChannel) <- 1
			}
		}

		<-castToSurvey(s.Survey.Get((string)(sdq.SurveyGenID))).FinalChannel

		survey = castToSurvey(s.Survey.Get((string)(sdq.SurveyGenID)))
		if sdq.QueryMode == 1 {
			for _, v := range survey.FinalResults {
				return &ServiceResult{Results: v}, nil
			}
		}
		log.LLvl1(s.ServerIdentity(), " END ROUND 2")

		ret := &ServiceResult{Results: survey.FinalResults[ResultID{ServerID: s.ServerIdentity().ID, SurveyID: sdq.SurveyID}]}
		return ret, nil

	}

	s.Survey.Put((string)(sdq.SurveyID), Survey{
		Store:           lib.NewStore(),
		Query:           *sdq,
		SurveySecretKey: surveySecret,

		IntermediateResults: make(map[ResultID]lib.FilteredResponse, 0),
	})

	// sends a signal to unlock waiting channel
	err := s.SendRaw(sdq.MessageSource, &SurveyGenerated{SurveyID: sdq.SurveyID})
	if err != nil {
		log.Error("sending error ", err)
	}

	return &ServiceResult{}, nil
}

// HandleSurveyResultsSharing shares the intermediate results (Round 1)
func (s *Service) HandleSurveyResultsSharing(resp *SurveyResultSharing) (network.Message, onet.ClientError) {
	defer s.Mutex.Unlock()
	s.Mutex.Lock()
	cpy, err := s.Survey.Get((string)(resp.SurveyGenID))

	var survey Survey
	if err != nil || cpy == nil || cpy.(Survey).IntermediateResults == nil {
		survey = Survey{}
		survey.IntermediateResults = make(map[ResultID]lib.FilteredResponse)
		survey.FirstTime = true
		survey.IntermediateChannel = make(chan int, 100)
		survey.FinalChannel = make(chan int, 100)
		survey.ShufflePrecompute = services.ReadPrecomputedFile(gobFile)
	} else {
		survey = cpy.(Survey)
	}
	survey.IntermediateResults[ResultID{ServerID: resp.ID.ServerID, SurveyID: resp.ID.SurveyID}] = resp.Result

	s.Survey.Put((string)(resp.SurveyGenID), survey)

	survey = castToSurvey(s.Survey.Get((string)(resp.SurveyGenID)))

	log.LLvl1(s.ServerIdentity(), " gets a survey response for ", resp.SurveyGenID, " from ", resp.ID.ServerID)
	log.LLvl1(s.ServerIdentity(), " now has ", len(survey.IntermediateResults), " surveys with response(s)")

	//if it is the last survey result needed then unblock the channel
	size := len(survey.IntermediateResults)

	if int64(size) == services.CountDPs(resp.MapDPs) {
		for i:= 0; i< int(resp.MapDPs[s.String()]); i++{
			(castToSurvey(s.Survey.Get((string)(resp.SurveyGenID))).IntermediateChannel) <- 1
		}
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
	log.LLvl1(s.ServerIdentity(), " gets a final survey result for from ", s.ServerIdentity().String())

	survey := castToSurvey(s.Survey.Get((string)(resp.SurveyGenID)))
	survey.FinalResults = resp.Results
	s.Survey.Put(string(resp.SurveyGenID), survey)

	// count the number of responses associated with each server or in other words the number of DPs (to unlock the FinalChannel)
	for k := range survey.IntermediateResults {
		if k.ServerID == s.ServerIdentity().ID {
			(castToSurvey(s.Survey.Get((string)(resp.SurveyGenID))).FinalChannel) <- 1
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
	survey := castToSurvey(s.Survey.Get(string(conf.Data)))

	switch tn.ProtocolName() {
	case protocols.ShufflingProtocolName:
		pi, err = protocols.NewShufflingProtocol(tn)
		if err != nil {
			return nil, err
		}
		shuffle := pi.(*protocols.ShufflingProtocol)

		shuffle.Proofs = survey.Query.Proofs
		shuffle.Precomputed = survey.ShufflePrecompute
		if tn.IsRoot() {
			targetShuffle := []lib.ProcessResponse{}
			for _, v := range survey.IntermediateResults {
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

		aux := survey.SurveySecretKey
		hashCreation.SurveySecretKey = &aux
		hashCreation.Proofs = survey.Query.Proofs
		hashCreation.NbrQueryAttributes = len(survey.Query.Where)

		if tn.IsRoot() {
			shuffledClientResponses := survey.PullShuffledProcessResponses()
			queryWhereToTag := []lib.ProcessResponse{}
			for _, v := range survey.Query.Where {
				tmp := lib.CipherVector{v.Value}
				queryWhereToTag = append(queryWhereToTag, lib.ProcessResponse{WhereEnc: tmp, GroupByEnc: nil, AggregatingAttributes: nil})
			}
			shuffledClientResponses = append(queryWhereToTag, shuffledClientResponses...)
			hashCreation.TargetOfSwitch = &shuffledClientResponses

			s.Survey.Put(string(target), survey)
		}
	case protocols.DROProtocolName:
		pi, err := protocols.NewShufflingProtocol(tn)
		if err != nil {
			return nil, err
		}

		shuffle := pi.(*protocols.ShufflingProtocol)
		shuffle.Proofs = true
		shuffle.Precomputed = survey.ShufflePrecompute

		if tn.IsRoot() {
			clientResponses := make([]lib.ProcessResponse, 0)
			noiseArray := lib.GenerateNoiseValues(1000, 0, 1, 0.1)
			for _, v := range noiseArray {
				clientResponses = append(clientResponses, lib.ProcessResponse{GroupByEnc: nil, AggregatingAttributes: lib.IntArrayToCipherVector([]int64{int64(v)})})
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
		keySwitch.Proofs = survey.Query.Proofs
		if tn.IsRoot() {
			coaggr := []lib.FilteredResponse{}

			if lib.DIFFPRI == true {
				coaggr = survey.PullDeliverableResults(true, survey.Noise)
			} else {
				coaggr = survey.PullDeliverableResults(false, lib.CipherText{})
			}

			keySwitch.TargetOfSwitch = &coaggr
			tmp := survey.Query.ClientPubKey
			keySwitch.TargetPublicKey = &tmp

			s.Survey.Put(string(target), survey)
		}
	default:
		return nil, errors.New("Service attempts to start an unknown protocol: " + tn.ProtocolName() + ".")
	}
	return pi, nil
}

// StartProtocol starts a specific protocol (Pipeline, Shuffling, etc.)
func (s *Service) StartProtocol(name string, targetSurvey SurveyID) (onet.ProtocolInstance, error) {
	tmp := castToSurvey(s.Survey.Get((string)(targetSurvey)))
	tree := tmp.Query.Roster.GenerateNaryTreeWithRoot(2, s.ServerIdentity())

	var tn *onet.TreeNodeInstance
	tn = s.NewTreeNodeInstance(tree, tree.Root, name)

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

	log.LLvl1(s.ServerIdentity(), " starts a Medco Protocol (Round 1) for survey", targetSurvey)

	// Tagging Phase
	start := lib.StartTimer(s.ServerIdentity().String() + "_TaggingPhase1")

	err := s.TaggingPhase(targetSurvey)
	if err != nil {
		log.Fatal("Error in the Tagging Phase (Round 1)")
	}

	lib.EndTimer(start)

	// Skip Collective Aggregation
	survey := castToSurvey(s.Survey.Get((string)(targetSurvey)))
	data := survey.PullLocallyAggregatedResponses()
	s.Survey.Put(string(targetSurvey), survey)

	survey = castToSurvey(s.Survey.Get((string)(targetSurvey)))
	survey.PushCothorityAggregatedFilteredResponses(data)
	s.Survey.Put(string(targetSurvey), survey)

	return nil
}

// StartServicePartTwo starts the second part of the service (with all its different steps/protocols)
func (s *Service) StartServicePartTwo(targetSurvey SurveyID, aggr bool) error {

	log.LLvl1(s.ServerIdentity(), " starts a Medco Protocol (Round 2) for survey", targetSurvey)

	// Tagging Phase
	start := lib.StartTimer(s.ServerIdentity().String() + "_TaggingPhase2")

	if !aggr {
		err := s.ShufflingPhase(targetSurvey)
		if err != nil {
			log.Fatal("Error in the Tagging Phase (Round 2)")
		}
	} else {
		aggrResponses := []lib.ProcessResponse{}

		survey := castToSurvey(s.Survey.Get((string)(targetSurvey)))
		for i, v := range survey.IntermediateResults {
			newProcessResponse := lib.ProcessResponse{GroupByEnc: v.GroupByEnc, AggregatingAttributes: v.AggregatingAttributes}
			for j, w := range survey.IntermediateResults {
				if j != i {
					cv := lib.NewCipherVector(len(newProcessResponse.AggregatingAttributes))
					cv.Add(newProcessResponse.AggregatingAttributes, w.AggregatingAttributes)
					if survey.Query.Proofs == true {
						proof := lib.PublishedSimpleAdditionProof{C1: newProcessResponse.AggregatingAttributes, C2: w.AggregatingAttributes, C1PlusC2: *cv}
						_ = proof
					}
					newProcessResponse.AggregatingAttributes = *cv
				}

			}
			aggrResponses = append(aggrResponses, newProcessResponse)
			break
		}
		survey.PushShuffledProcessResponses(aggrResponses)
		s.Survey.Put(string(targetSurvey), survey)
	}
	lib.EndTimer(start)

	//skip collective aggregation
	survey := castToSurvey(s.Survey.Get((string)(targetSurvey)))
	shuffledFinalResponsesUnformatted := survey.PullShuffledProcessResponses()
	s.Survey.Put(string(targetSurvey), survey)

	shuffledFinalResponsesFormat := make([]lib.FilteredResponse, len(shuffledFinalResponsesUnformatted))
	for i, v := range shuffledFinalResponsesUnformatted {
		shuffledFinalResponsesFormat[i].GroupByEnc = v.GroupByEnc
		shuffledFinalResponsesFormat[i].AggregatingAttributes = v.AggregatingAttributes
	}

	// here we use the table to store the responses used in key switching
	survey = castToSurvey(s.Survey.Get((string)(targetSurvey)))
	survey.PushQuerierKeyEncryptedResponses(shuffledFinalResponsesFormat)
	s.Survey.Put(string(targetSurvey), survey)

	// DRO Phase
	if lib.DIFFPRI == true {
		start := lib.StartTimer(s.ServerIdentity().String() + "_DROPhase")

		s.DROPhase(survey.Query.SurveyGenID)

		lib.EndTimer(start)
	}

	err := s.KeySwitchingPhase(survey.Query.SurveyGenID)

	if err != nil {
		log.Fatal("Error in the Key Switching Phase")
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

	survey := castToSurvey(s.Survey.Get((string)(targetSurvey)))
	survey.PushShuffledProcessResponses(shufflingResult)
	s.Survey.Put(string(targetSurvey), survey)
	return err
}

// TaggingPhase performs the private grouping on the currently collected data.
func (s *Service) TaggingPhase(targetSurvey SurveyID) error {
	survey := castToSurvey(s.Survey.Get((string)(targetSurvey)))

	if len(survey.ShuffledProcessResponses) == 0 {
		log.LLvl1(s.ServerIdentity(), " for survey", targetSurvey, "has no data to det tag")
		return nil
	}

	pi, err := s.StartProtocol(protocols.DeterministicTaggingProtocolName, targetSurvey)
	if err != nil {
		return err
	}

	deterministicTaggingResult := <-pi.(*protocols.DeterministicTaggingProtocol).FeedbackChannel

	queryWhereTag := []lib.WhereQueryAttributeTagged{}
	for i, v := range deterministicTaggingResult[:len(survey.Query.Where)] {
		newElem := lib.WhereQueryAttributeTagged{Name: survey.Query.Where[i].Name, Value: v.DetTagWhere[0]}
		queryWhereTag = append(queryWhereTag, newElem)
	}
	deterministicTaggingResult = deterministicTaggingResult[len(survey.Query.Where):]
	filteredResponses := services.FilterResponses(survey.Query.Predicate, queryWhereTag, deterministicTaggingResult)
	survey.PushDeterministicFilteredResponses(filteredResponses, s.ServerIdentity().String(), survey.Query.Proofs)

	s.Survey.Put(string(targetSurvey), survey)
	return err
}

// DROPhase shuffles the list of noise values.
func (s *Service) DROPhase(targetSurvey SurveyID) error {
	pi, err := s.StartProtocol(protocols.DROProtocolName, targetSurvey)
	if err != nil {
		return err
	}

	shufflingResult := <-pi.(*protocols.ShufflingProtocol).FeedbackChannel

	survey := castToSurvey(s.Survey.Get((string)(targetSurvey)))
	survey.Noise = shufflingResult[0].AggregatingAttributes[0]
	s.Survey.Put(string(targetSurvey), survey)
	return nil
}

// KeySwitchingPhase performs the switch to the querier's key on the currently aggregated data.
func (s *Service) KeySwitchingPhase(targetSurvey SurveyID) error {
	pi, err := s.StartProtocol(protocols.KeySwitchingProtocolName, targetSurvey)
	if err != nil {
		return err
	}
	keySwitchedAggregatedResponses := <-pi.(*protocols.KeySwitchingProtocol).FeedbackChannel

	survey := castToSurvey(s.Survey.Get((string)(targetSurvey)))
	survey.PushQuerierKeyEncryptedResponses(keySwitchedAggregatedResponses)
	s.Survey.Put(string(targetSurvey), survey)
	return err
}
