package servicesunlynxdefault

import (
	"github.com/Knetic/govaluate"
	"github.com/btcsuite/goleveldb/leveldb/errors"
	"github.com/dedis/kyber"
	"github.com/dedis/onet"
	"github.com/dedis/onet/log"
	"github.com/dedis/onet/network"
	"github.com/fanliao/go-concurrentMap"
	"github.com/lca1/unlynx/lib"
	"github.com/lca1/unlynx/lib/diffprivacy"
	"github.com/lca1/unlynx/lib/shuffle"
	"github.com/lca1/unlynx/lib/store"
	"github.com/lca1/unlynx/lib/tools"
	"github.com/lca1/unlynx/protocols"
	"github.com/lca1/unlynx/services/default/data"
	"github.com/satori/go.uuid"
	"strconv"
	"time"
)

// ServiceName is the registered name for the unlynx service.
const ServiceName = "UnLynx"

const gobFile = "pre_compute_multiplications.gob"

// SurveyID unique ID for each survey.
type SurveyID string

// SurveyCreationQuery is used to trigger the creation of a survey
type SurveyCreationQuery struct {
	SurveyID     SurveyID
	Roster       onet.Roster
	ClientPubKey kyber.Point
	MapDPs       map[string]int64
	Proofs       bool
	AppFlag      bool

	// query statement
	Sum       []string
	Count     bool
	Where     []libunlynx.WhereQueryAttribute
	Predicate string
	GroupBy   []string
}

// Survey represents a survey with the corresponding params
type Survey struct {
	*libunlynxstore.Store
	Query             SurveyCreationQuery
	SurveySecretKey   kyber.Scalar
	ShufflePrecompute []libunlynx.CipherVectorScalar
	Lengths           [][]int
	TargetOfSwitch    []libunlynx.ProcessResponse

	// channels
	SurveyChannel chan int // To wait for the survey to be created before loading data
	DpChannel     chan int // To wait for all data to be read before starting unlynx service protocol
	DDTChannel    chan int // To wait for all nodes to finish the tagging before continuing

	Noise libunlynx.CipherText
}

func castToSurvey(object interface{}, err error) Survey {
	if err != nil {
		log.Fatal("Error reading map")
	}
	return object.(Survey)
}

// MsgTypes defines the Message Type ID for all the service's intra-messages.
type MsgTypes struct {
	msgSurveyCreationQuery network.MessageTypeID
	msgSurveyResultsQuery  network.MessageTypeID
	msgDDTfinished         network.MessageTypeID
}

var msgTypes = MsgTypes{}

func init() {
	onet.RegisterNewService(ServiceName, NewService)

	msgTypes.msgSurveyCreationQuery = network.RegisterMessage(&SurveyCreationQuery{})
	network.RegisterMessage(&SurveyResponseQuery{})
	msgTypes.msgSurveyResultsQuery = network.RegisterMessage(&SurveyResultsQuery{})
	msgTypes.msgDDTfinished = network.RegisterMessage(&DDTfinished{})

	network.RegisterMessage(&ServiceState{})
	network.RegisterMessage(&ServiceResult{})
}

// DDTfinished is used to ensure that all servers perform the shuffling+DDT before collectively aggregating the results
type DDTfinished struct {
	SurveyID SurveyID
}

// SurveyResponseQuery is used to ask a client for its response to a survey.
type SurveyResponseQuery struct {
	SurveyID  SurveyID
	Responses []libunlynx.DpResponseToSend
}

// SurveyResultsQuery is used by querier to ask for the response of the survey.
type SurveyResultsQuery struct {
	IntraMessage bool
	SurveyID     SurveyID
	ClientPublic kyber.Point
}

// ServiceState represents the service "state".
type ServiceState struct {
	SurveyID SurveyID
}

// ServiceResult will contain final results of a survey and be sent to querier.
type ServiceResult struct {
	Results []libunlynx.FilteredResponse
}

// Service defines a service in unlynx with a survey.
type Service struct {
	*onet.ServiceProcessor

	Survey *concurrent.ConcurrentMap
}

// NewService constructor which registers the needed messages.
func NewService(c *onet.Context) (onet.Service, error) {
	newUnLynxInstance := &Service{
		ServiceProcessor: onet.NewServiceProcessor(c),
		Survey:           concurrent.NewConcurrentMap(),
	}
	var cerr error
	if cerr = newUnLynxInstance.RegisterHandler(newUnLynxInstance.HandleSurveyCreationQuery); cerr != nil {
		log.Fatal("Wrong Handler.", cerr)
	}
	if cerr = newUnLynxInstance.RegisterHandler(newUnLynxInstance.HandleSurveyResponseQuery); cerr != nil {
		log.Fatal("Wrong Handler.", cerr)
	}
	if cerr = newUnLynxInstance.RegisterHandler(newUnLynxInstance.HandleSurveyResultsQuery); cerr != nil {
		log.Fatal("Wrong Handler.", cerr)
	}
	if cerr = newUnLynxInstance.RegisterHandler(newUnLynxInstance.HandleDDTfinished); cerr != nil {
		log.Fatal("Wrong Handler.", cerr)
	}

	c.RegisterProcessor(newUnLynxInstance, msgTypes.msgSurveyCreationQuery)
	c.RegisterProcessor(newUnLynxInstance, msgTypes.msgSurveyResultsQuery)
	c.RegisterProcessor(newUnLynxInstance, msgTypes.msgDDTfinished)
	return newUnLynxInstance, cerr
}

// Process implements the processor interface and is used to recognize messages broadcasted between servers
func (s *Service) Process(msg *network.Envelope) {
	if msg.MsgType.Equal(msgTypes.msgSurveyCreationQuery) {
		tmp := (msg.Msg).(*SurveyCreationQuery)
		s.HandleSurveyCreationQuery(tmp)
	} else if msg.MsgType.Equal(msgTypes.msgSurveyResultsQuery) {
		tmp := (msg.Msg).(*SurveyResultsQuery)
		s.HandleSurveyResultsQuery(tmp)
	} else if msg.MsgType.Equal(msgTypes.msgDDTfinished) {
		tmp := (msg.Msg).(*DDTfinished)
		s.HandleDDTfinished(tmp)
	}
}

// PushData is used to store incoming data by servers
func (s *Service) PushData(resp *SurveyResponseQuery, proofs bool) {
	survey := castToSurvey(s.Survey.Get((string)(resp.SurveyID)))
	for _, v := range resp.Responses {
		dr := libunlynx.DpResponse{}
		dr.FromDpResponseToSend(v)
		survey.InsertDpResponse(dr, proofs, survey.Query.GroupBy, survey.Query.Sum, survey.Query.Where)
	}
	s.Survey.Put(string(resp.SurveyID), survey)

	log.Lvl1(s.ServerIdentity(), " uploaded response data for survey ", resp.SurveyID)
}

// Query Handlers
//______________________________________________________________________________________________________________________

// HandleSurveyCreationQuery handles the reception of a survey creation query by instantiating the corresponding survey.
func (s *Service) HandleSurveyCreationQuery(recq *SurveyCreationQuery) (network.Message, error) {
	log.Lvl1(s.ServerIdentity().String(), " received a Survey Creation Query")

	// if this server is the one receiving the query from the client
	if recq.SurveyID == "" {
		id, _ := uuid.NewV4()
		newID := SurveyID(id.String())
		recq.SurveyID = newID

		log.Lvl1(s.ServerIdentity().String(), " handles this new survey ", recq.SurveyID)

		// broadcasts the query
		err := libunlynxtools.SendISMOthers(s.ServiceProcessor, &recq.Roster, recq)
		if err != nil {
			log.Error("broadcasting error ", err)
		}
		log.Lvl1(s.ServerIdentity(), " initiated the survey ", newID)

	}

	// chooses an ephemeral secret for this survey
	surveySecret := libunlynx.SuiTe.Scalar().Pick(libunlynx.SuiTe.RandomStream())

	// prepares the precomputation for shuffling
	lineSize := int(len(recq.Sum)) + int(len(recq.Where)) + int(len(recq.GroupBy)) + 1 // + 1 is for the possible count attribute
	precomputeShuffle := libunlynxshuffle.PrecomputationWritingForShuffling(recq.AppFlag, gobFile, s.ServerIdentity().String(), surveySecret, recq.Roster.Aggregate, lineSize)

	// survey instantiation
	s.Survey.Put((string)(recq.SurveyID), Survey{
		Store:             libunlynxstore.NewStore(),
		Query:             *recq,
		SurveySecretKey:   surveySecret,
		ShufflePrecompute: precomputeShuffle,

		SurveyChannel: make(chan int, 100),
		DpChannel:     make(chan int, 100),
		DDTChannel:    make(chan int, 100),
	})

	log.Lvl1(s.ServerIdentity(), " created the survey ", recq.SurveyID)
	// if it is a app download the data from the test file
	if recq.AppFlag {
		index := 0
		for index = 0; index < len(recq.Roster.List); index++ {
			if recq.Roster.List[index].String() == s.ServerIdentity().String() {
				break
			}
		}
		testData := dataunlynx.ReadDataFromFile("unlynx_test_data.txt")
		resp := EncryptDataToSurvey(s.ServerIdentity().String(), recq.SurveyID, testData[strconv.Itoa(index)], recq.Roster.Aggregate, 1, recq.Count)
		s.PushData(resp, recq.Proofs)

		//number of data providers who have already pushed the data
		castToSurvey(s.Survey.Get((string)(resp.SurveyID))).DpChannel <- 1
	}

	// update surveyChannel so that the server knows he can start to process data from DPs
	castToSurvey(s.Survey.Get((string)(recq.SurveyID))).SurveyChannel <- 1
	return &ServiceState{recq.SurveyID}, nil
}

// HandleSurveyResponseQuery handles a survey answers submission by a subject.
func (s *Service) HandleSurveyResponseQuery(resp *SurveyResponseQuery) (network.Message, error) {
	var el interface{}
	el = nil
	for el == nil {
		el, _ = s.Survey.Get((string)(resp.SurveyID))

		if el != nil {
			break
		}

		time.Sleep(time.Millisecond * 100)
	}

	survey := el.(Survey)
	if survey.Query.SurveyID == resp.SurveyID {
		<-castToSurvey(s.Survey.Get((string)(resp.SurveyID))).SurveyChannel

		s.PushData(resp, survey.Query.Proofs)

		//unblock the channel to allow another DP to send its data
		castToSurvey(s.Survey.Get((string)(resp.SurveyID))).SurveyChannel <- 1
		//number of data providers who have already pushed the data
		castToSurvey(s.Survey.Get((string)(resp.SurveyID))).DpChannel <- 1

		return &ServiceState{"1"}, nil
	}

	log.Lvl1(s.ServerIdentity(), " does not know about this survey!")
	return &ServiceState{resp.SurveyID}, nil
}

// HandleSurveyResultsQuery handles the survey result query by the surveyor.
func (s *Service) HandleSurveyResultsQuery(resq *SurveyResultsQuery) (network.Message, error) {

	log.Lvl1(s.ServerIdentity(), " received a survey result query")

	survey := castToSurvey(s.Survey.Get((string)(resq.SurveyID)))
	survey.Query.ClientPubKey = resq.ClientPublic
	s.Survey.Put(string(resq.SurveyID), survey)

	if resq.IntraMessage == false {
		resq.IntraMessage = true

		err := libunlynxtools.SendISMOthers(s.ServiceProcessor, &survey.Query.Roster, resq)
		if err != nil {
			log.Error("broadcasting error ", err)
		}
		s.StartService(resq.SurveyID, true)

		log.Lvl1(s.ServerIdentity(), " completed the query processing...")

		survey := castToSurvey(s.Survey.Get((string)(resq.SurveyID)))
		results := survey.PullDeliverableResults(false, libunlynx.CipherText{})
		s.Survey.Put(string(resq.SurveyID), survey)

		return &ServiceResult{Results: results}, nil
	}

	s.StartService(resq.SurveyID, false)
	return nil, nil
}

// HandleDDTfinished handles the message
func (s *Service) HandleDDTfinished(recq *DDTfinished) (network.Message, error) {
	castToSurvey(s.Survey.Get((string)(recq.SurveyID))).DDTChannel <- 1
	return nil, nil
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
	case protocolsunlynx.ShufflingProtocolName:
		pi, err = protocolsunlynx.NewShufflingProtocol(tn)
		if err != nil {
			return nil, err
		}
		shuffle := pi.(*protocolsunlynx.ShufflingProtocol)

		shuffle.Proofs = survey.Query.Proofs
		shuffle.Precomputed = survey.ShufflePrecompute
		if tn.IsRoot() {
			dpResponses := survey.PullDpResponses()
			var toShuffleCV []libunlynx.CipherVector
			toShuffleCV, survey.Lengths = protocolsunlynx.ProcessResponseToMatrixCipherText(dpResponses)
			shuffle.TargetOfShuffle = &toShuffleCV

			s.Survey.Put(string(target), survey)
		}

	case protocolsunlynx.DeterministicTaggingProtocolName:
		pi, err = protocolsunlynx.NewDeterministicTaggingProtocol(tn)
		if err != nil {
			return nil, err
		}
		hashCreation := pi.(*protocolsunlynx.DeterministicTaggingProtocol)

		aux := survey.SurveySecretKey
		hashCreation.SurveySecretKey = &aux
		hashCreation.Proofs = survey.Query.Proofs
		if tn.IsRoot() {
			shuffledClientResponses := survey.PullShuffledProcessResponses()

			var queryWhereToTag []libunlynx.ProcessResponse
			for _, v := range survey.Query.Where {
				tmp := libunlynx.CipherVector{v.Value}
				queryWhereToTag = append(queryWhereToTag, libunlynx.ProcessResponse{WhereEnc: tmp, GroupByEnc: nil, AggregatingAttributes: nil})
			}
			shuffledClientResponses = append(queryWhereToTag, shuffledClientResponses...)
			tmpDeterministicTOS := protocolsunlynx.ProcessResponseToCipherVector(shuffledClientResponses)
			survey.TargetOfSwitch = shuffledClientResponses
			s.Survey.Put(string(target), survey)

			hashCreation.TargetOfSwitch = &tmpDeterministicTOS
		}

	case protocolsunlynx.CollectiveAggregationProtocolName:
		pi, err = protocolsunlynx.NewCollectiveAggregationProtocol(tn)
		if err != nil {
			return nil, err
		}

		// waits for all other nodes to finish the tagging phase
		groupedData := survey.PullLocallyAggregatedResponses()
		s.Survey.Put(string(target), survey)

		pi.(*protocolsunlynx.CollectiveAggregationProtocol).GroupedData = &groupedData
		pi.(*protocolsunlynx.CollectiveAggregationProtocol).Proofs = survey.Query.Proofs

		counter := len(tn.Roster().List) - 1
		for counter > 0 {
			counter = counter - (<-castToSurvey(s.Survey.Get(string(conf.Data))).DDTChannel)
		}

	case protocolsunlynx.DROProtocolName:
		pi, err := protocolsunlynx.NewShufflingProtocol(tn)
		if err != nil {
			return nil, err
		}

		shuffle := pi.(*protocolsunlynx.ShufflingProtocol)
		shuffle.Proofs = true
		shuffle.Precomputed = nil

		if tn.IsRoot() {
			clientResponses := make([]libunlynx.ProcessResponse, 0)
			noiseArray := libunlynxdiffprivacy.GenerateNoiseValues(1000, 0, 1, 0.1)
			for _, v := range noiseArray {
				clientResponses = append(clientResponses, libunlynx.ProcessResponse{GroupByEnc: nil, AggregatingAttributes: libunlynx.IntArrayToCipherVector([]int64{int64(v)})})
			}
			var toShuffleCV []libunlynx.CipherVector
			toShuffleCV, survey.Lengths = protocolsunlynx.ProcessResponseToMatrixCipherText(clientResponses)
			shuffle.TargetOfShuffle = &toShuffleCV
		}
		return pi, nil

	case protocolsunlynx.KeySwitchingProtocolName:
		pi, err = protocolsunlynx.NewKeySwitchingProtocol(tn)
		if err != nil {
			return nil, err
		}

		keySwitch := pi.(*protocolsunlynx.KeySwitchingProtocol)
		keySwitch.Proofs = survey.Query.Proofs
		if tn.IsRoot() {
			var coaggr []libunlynx.FilteredResponse

			if libunlynx.DIFFPRI == true {
				coaggr = survey.PullCothorityAggregatedFilteredResponses(true, survey.Noise)
			} else {
				coaggr = survey.PullCothorityAggregatedFilteredResponses(false, libunlynx.CipherText{})
			}
			var tmpKeySwitchingCV libunlynx.CipherVector
			tmpKeySwitchingCV, survey.Lengths = protocolsunlynx.FilteredResponseToCipherVector(coaggr)
			keySwitch.TargetOfSwitch = &tmpKeySwitchingCV
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
	if err != nil {
		log.Fatal("Error running" + name)
	}

	s.RegisterProtocolInstance(pi)
	go pi.Dispatch()
	go pi.Start()

	return pi, err
}

// Service Phases
//______________________________________________________________________________________________________________________

// StartService starts the service (with all its different steps/protocols)
func (s *Service) StartService(targetSurvey SurveyID, root bool) error {

	log.Lvl1(s.ServerIdentity(), " is waiting on channel")
	<-castToSurvey(s.Survey.Get((string)(targetSurvey))).SurveyChannel

	survey := castToSurvey(s.Survey.Get((string)(targetSurvey)))

	counter := survey.Query.MapDPs[s.ServerIdentity().String()]

	for counter > int64(0) {
		log.Lvl1(s.ServerIdentity(), " is waiting for ", counter, " data providers to send their data")
		counter = counter - int64(<-castToSurvey(s.Survey.Get((string)(targetSurvey))).DpChannel)
	}
	log.Lvl1("All data providers (", survey.Query.MapDPs[s.ServerIdentity().String()], ") for server ", s.ServerIdentity(), " have sent their data")

	log.Lvl1(s.ServerIdentity(), " starts a UnLynx Protocol for survey ", targetSurvey)

	target := castToSurvey(s.Survey.Get((string)(targetSurvey)))

	// Shuffling Phase
	start := libunlynx.StartTimer(s.ServerIdentity().String() + "_ShufflingPhase")

	err := s.ShufflingPhase(survey.Query.SurveyID)
	if err != nil {
		log.Fatal("Error in the Shuffling Phase")
	}

	libunlynx.EndTimer(start)
	// Tagging Phase
	start = libunlynx.StartTimer(s.ServerIdentity().String() + "_TaggingPhase")

	err = s.TaggingPhase(target.Query.SurveyID)
	if err != nil {
		log.Fatal("Error in the Tagging Phase")
	}

	// broadcasts the query to unlock waiting channel
	aux := target.Query.Roster
	err = libunlynxtools.SendISMOthers(s.ServiceProcessor, &aux, &DDTfinished{SurveyID: targetSurvey})
	if err != nil {
		log.Error("broadcasting error ", err)
	}

	libunlynx.EndTimer(start)

	// Aggregation Phase
	if root == true {
		start := libunlynx.StartTimer(s.ServerIdentity().String() + "_AggregationPhase")

		err = s.AggregationPhase(target.Query.SurveyID)
		if err != nil {
			log.Fatal("Error in the Aggregation Phase")
		}

		libunlynx.EndTimer(start)
	}

	// DRO Phase
	if root == true && libunlynx.DIFFPRI == true {
		start := libunlynx.StartTimer(s.ServerIdentity().String() + "_DROPhase")

		s.DROPhase(target.Query.SurveyID)

		libunlynx.EndTimer(start)
	}

	// Key Switch Phase
	if root == true {
		start := libunlynx.StartTimer(s.ServerIdentity().String() + "_KeySwitchingPhase")

		s.KeySwitchingPhase(target.Query.SurveyID)

		libunlynx.EndTimer(start)
	}

	return nil
}

// ShufflingPhase performs the shuffling of the ClientResponses
func (s *Service) ShufflingPhase(targetSurvey SurveyID) error {
	survey := castToSurvey(s.Survey.Get((string)(targetSurvey)))

	if len(survey.DpResponses) == 0 && len(survey.DpResponsesAggr) == 0 {
		log.Lvl1(s.ServerIdentity(), " no data to shuffle")
		return nil
	}

	pi, err := s.StartProtocol(protocolsunlynx.ShufflingProtocolName, targetSurvey)
	if err != nil {
		return err
	}
	tmpShufflingResult := <-pi.(*protocolsunlynx.ShufflingProtocol).FeedbackChannel
	shufflingResult := protocolsunlynx.MatrixCipherTextToProcessResponse(tmpShufflingResult, castToSurvey(s.Survey.Get((string)(targetSurvey))).Lengths)

	survey.PushShuffledProcessResponses(shufflingResult)
	s.Survey.Put(string(targetSurvey), survey)
	return err
}

// TaggingPhase performs the private grouping on the currently collected data.
func (s *Service) TaggingPhase(targetSurvey SurveyID) error {
	survey := castToSurvey(s.Survey.Get((string)(targetSurvey)))

	if len(survey.ShuffledProcessResponses) == 0 {
		log.Lvl1(s.ServerIdentity(), "  for survey ", survey.Query.SurveyID, " has no data to det tag")
		return nil
	}

	pi, err := s.StartProtocol(protocolsunlynx.DeterministicTaggingProtocolName, targetSurvey)
	if err != nil {
		return err
	}

	tmpDeterministicTaggingResult := <-pi.(*protocolsunlynx.DeterministicTaggingProtocol).FeedbackChannel
	deterministicTaggingResult := protocolsunlynx.DeterCipherVectorToProcessResponseDet(tmpDeterministicTaggingResult, castToSurvey(s.Survey.Get((string)(targetSurvey))).TargetOfSwitch)

	var queryWhereTag []libunlynx.WhereQueryAttributeTagged
	for i, v := range deterministicTaggingResult[:len(survey.Query.Where)] {
		newElem := libunlynx.WhereQueryAttributeTagged{Name: survey.Query.Where[i].Name, Value: v.DetTagWhere[0]}
		queryWhereTag = append(queryWhereTag, newElem)
	}
	deterministicTaggingResult = deterministicTaggingResult[len(survey.Query.Where):]

	var filteredResponses []libunlynx.FilteredResponseDet
	if survey.Query.Predicate == "" || len(queryWhereTag) == 0 {
		filteredResponses = FilterNone(deterministicTaggingResult)
	} else {
		filteredResponses = FilterResponses(survey.Query.Predicate, queryWhereTag, deterministicTaggingResult)
	}

	survey.PushDeterministicFilteredResponses(filteredResponses, s.ServerIdentity().String(), survey.Query.Proofs)
	s.Survey.Put(string(targetSurvey), survey)
	return err
}

// AggregationPhase performs the per-group aggregation on the currently grouped data.
func (s *Service) AggregationPhase(targetSurvey SurveyID) error {
	pi, err := s.StartProtocol(protocolsunlynx.CollectiveAggregationProtocolName, targetSurvey)
	if err != nil {
		return err
	}
	cothorityAggregatedData := <-pi.(*protocolsunlynx.CollectiveAggregationProtocol).FeedbackChannel

	survey := castToSurvey(s.Survey.Get((string)(targetSurvey)))
	survey.PushCothorityAggregatedFilteredResponses(cothorityAggregatedData.GroupedData)
	s.Survey.Put(string(targetSurvey), survey)
	return nil
}

// DROPhase shuffles the list of noise values.
func (s *Service) DROPhase(targetSurvey SurveyID) error {
	pi, err := s.StartProtocol(protocolsunlynx.DROProtocolName, targetSurvey)
	if err != nil {
		return err
	}

	survey := castToSurvey(s.Survey.Get((string)(targetSurvey)))

	tmpShufflingResult := <-pi.(*protocolsunlynx.ShufflingProtocol).FeedbackChannel
	shufflingResult := protocolsunlynx.MatrixCipherTextToProcessResponse(tmpShufflingResult, survey.Lengths)

	survey.Noise = shufflingResult[0].AggregatingAttributes[0]
	s.Survey.Put(string(targetSurvey), survey)
	return nil
}

// KeySwitchingPhase performs the switch to the querier's key on the currently aggregated data.
func (s *Service) KeySwitchingPhase(targetSurvey SurveyID) error {
	pi, err := s.StartProtocol(protocolsunlynx.KeySwitchingProtocolName, targetSurvey)
	if err != nil {
		return err
	}

	survey := castToSurvey(s.Survey.Get((string)(targetSurvey)))

	tmpKeySwitchedAggregatedResponses := <-pi.(*protocolsunlynx.KeySwitchingProtocol).FeedbackChannel
	keySwitchedAggregatedResponses := protocolsunlynx.CipherVectorToFilteredResponse(tmpKeySwitchedAggregatedResponses, survey.Lengths)

	survey.PushQuerierKeyEncryptedResponses(keySwitchedAggregatedResponses)
	s.Survey.Put(string(targetSurvey), survey)
	return err
}

// Support Functions
//______________________________________________________________________________________________________________________

// FilterResponses evaluates the predicate and keeps the entries that satisfy the conditions
func FilterResponses(pred string, whereQueryValues []libunlynx.WhereQueryAttributeTagged, responsesToFilter []libunlynx.ProcessResponseDet) []libunlynx.FilteredResponseDet {
	var result []libunlynx.FilteredResponseDet
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
			result = append(result, libunlynx.FilteredResponseDet{DetTagGroupBy: v.DetTagGroupBy, Fr: libunlynx.FilteredResponse{GroupByEnc: v.PR.GroupByEnc, AggregatingAttributes: v.PR.AggregatingAttributes}})
		}
	}
	return result
}

// FilterNone skips the filtering of attributes when there is no predicate (the number of where attributes == 0)
func FilterNone(responsesToFilter []libunlynx.ProcessResponseDet) []libunlynx.FilteredResponseDet {
	var result []libunlynx.FilteredResponseDet
	for _, v := range responsesToFilter {
		result = append(result, libunlynx.FilteredResponseDet{DetTagGroupBy: v.DetTagGroupBy, Fr: libunlynx.FilteredResponse{GroupByEnc: v.PR.GroupByEnc, AggregatingAttributes: v.PR.AggregatingAttributes}})
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
