package services

import (
	"os"
	"reflect"
	"strconv"

	"github.com/JoaoAndreSa/MedCo/lib"
	"github.com/JoaoAndreSa/MedCo/protocols"
	"github.com/JoaoAndreSa/MedCo/services/data"
	"github.com/btcsuite/goleveldb/leveldb/errors"
	"github.com/satori/go.uuid"
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/crypto.v0/random"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/dedis/onet.v1/network"
	"strings"
	"sync"
)

// ServiceName is the registered name for the medco service.
const ServiceName = "MedCo"

// DROProtocolName is the registered name for the medco service protocol.
const DROProtocolName = "DRO"

const gobFile = "pre_compute_multiplications.gob"
const testDataFile = "medco_test_data.txt"

type MsgTypes struct {
	msgSurveyCreationQuery 			network.MessageTypeID
	msgSurveyResponseSharing  		network.MessageTypeID
	msgSurveyFinalResponseSharing      	network.MessageTypeID
	msgSurveyResultsQuery             	network.MessageTypeID
	msgDDTfinished				network.MessageTypeID
}

var msgTypes = MsgTypes{}

func init() {
	onet.RegisterNewService(ServiceName, NewService)
	network.RegisterMessage(&lib.ClientResponse{})
	msgTypes.msgSurveyCreationQuery = network.RegisterMessage(&SurveyCreationQuery{})
	msgTypes.msgSurveyResponseSharing = network.RegisterMessage(&SurveyResponseSharing{})
	msgTypes.msgSurveyFinalResponseSharing = network.RegisterMessage(&SurveyFinalResponseSharing{})
	network.RegisterMessage(&SurveyResponseQuery{})
	network.RegisterMessage(&SurveyResultResponse{})
	msgTypes.msgSurveyResultsQuery = network.RegisterMessage(&SurveyResultsQuery{})
	network.RegisterMessage(&ServiceResponse{})
	msgTypes.msgDDTfinished = network.RegisterMessage(&DDTfinished{})
}

// SurveyCreationQuery is used to trigger the creation of a survey.
type SurveyCreationQuery struct {
	SurveyGenID       *lib.SurveyID
	SurveyID          *lib.SurveyID
	Roster            onet.Roster
	SurveyDescription lib.SurveyDescription
	Proofs            bool
	AppFlag           bool
	QuerySubject      []lib.ClientResponse
	ClientPubKey      abstract.Point
	DataToProcess     []lib.ClientResponse
	NbrDPs            map[string]int64
	AggregationTotal  int64
}

// DDTfinished is used to ensure that all servers perform the shuffling+DDT before collectively aggregating the results
type DDTfinished struct{}

// SurveyResponseQuery is used to ask a client for its response to a survey.
type SurveyResponseQuery struct {
	SurveyID  lib.SurveyID
	Responses []lib.ClientResponse
}

// SurveyResultsQuery is used by querier to ask for the response of the survey.
type SurveyResultsQuery struct {
	IntraMessage bool
	SurveyID     lib.SurveyID
	ClientPublic abstract.Point
}

// ServiceResponse represents the service "state".
type ServiceResponse struct {
	SurveyID lib.SurveyID
}

// SurveyResultResponse will contain final results of a survey and be sent to querier.
type SurveyResultResponse struct {
	Results []lib.ClientResponse
}

// SurveyResponseSharing represents a message containing a survey and its result (used in i2b2 version to share results
// between servers
type SurveyResponseSharing struct {
	Survey lib.Survey
}

// SurveyFinalResponseSharing represents a message containing survey ids and responses (i2b2)
type SurveyFinalResponseSharing struct {
	Responses []FinalResponsesIds
}

// FinalResponsesIds represents a survey response and the corresponding server Id (i2b2)
type FinalResponsesIds struct {
	ID network.ServerIdentityID
	CR lib.ClientResponse
}

// Service defines a service in medco case with a survey.
type Service struct {
	*onet.ServiceProcessor
	homePath string

	survey                       map[lib.SurveyID]lib.Survey
	surveyWithResponses          map[lib.SurveyID]lib.Survey
	surveyCounter                map[lib.SurveyID]int
	appFlag                      bool
	nbrDPs                       int64    // Number of data providers associated with each server
	surveyChannel                chan int // To wait for the survey to be created before loading data
	dpChannel                    chan int // To wait for all data to be read before starting medco service protocol.
	sharingResponsesChannel      chan int
	sharingFinalResponsesChannel chan int
	DDTChannel                   chan int
	EndService                   chan int
	noise                        lib.CipherText
	current                      lib.SurveyID
	nbrLocalSurveys              int
	sentResponses                []FinalResponsesIds
	finalResponses               []FinalResponsesIds
	mutex                        sync.Mutex

	TargetSurvey              *lib.Survey
	Proofs                    bool
}

// NewService constructor which registers the needed messages.
func NewService(c *onet.Context) onet.Service {
	newMedCoInstance := &Service{
		ServiceProcessor: onet.NewServiceProcessor(c),
		//homePath:                     path,
		survey:                       make(map[lib.SurveyID]lib.Survey, 0),
		surveyWithResponses:          make(map[lib.SurveyID]lib.Survey, 0),
		surveyCounter:                make(map[lib.SurveyID]int, 0),
		surveyChannel:                make(chan int, 100),
		dpChannel:                    make(chan int, 100),
		sharingResponsesChannel:      make(chan int, 100),
		sharingFinalResponsesChannel: make(chan int, 100),
		DDTChannel:                   make(chan int, 100),
		EndService:                   make(chan int, 1),
	}
	if cerr := newMedCoInstance.RegisterHandler(newMedCoInstance.HandleSurveyCreationQuery); cerr != nil {
		log.Fatal("Wrong Handler.", cerr)
	}
	if cerr := newMedCoInstance.RegisterHandler(newMedCoInstance.HandleSurveyResponseQuery); cerr != nil {
		log.Fatal("Wrong Handler.", cerr)
	}
	if cerr := newMedCoInstance.RegisterHandler(newMedCoInstance.HandleSurveyResponseSharing); cerr != nil {
		log.Fatal("Wrong Handler.", cerr)
	}
	if cerr := newMedCoInstance.RegisterHandler(newMedCoInstance.HandleSurveyFinalResponseSharing); cerr != nil {
		log.Fatal("Wrong Handler.", cerr)
	}
	if cerr := newMedCoInstance.RegisterHandler(newMedCoInstance.HandleSurveyResultsQuery); cerr != nil {
		log.Fatal("Wrong Handler.", cerr)
	}
	if cerr := newMedCoInstance.RegisterHandler(newMedCoInstance.HandleDDTfinished); cerr != nil {
		log.Fatal("Wrong Handler.", cerr)
	}

	c.RegisterProcessor(newMedCoInstance, msgTypes.msgSurveyCreationQuery)
	c.RegisterProcessor(newMedCoInstance, msgTypes.msgSurveyResponseSharing)
	c.RegisterProcessor(newMedCoInstance, msgTypes.msgSurveyFinalResponseSharing)
	c.RegisterProcessor(newMedCoInstance, msgTypes.msgSurveyResultsQuery)
	c.RegisterProcessor(newMedCoInstance, msgTypes.msgDDTfinished)

	newMedCoInstance.ProtocolRegister("DROInService", newMedCoInstance.NewDROProtocol)
	return newMedCoInstance
}

// Process implements the processor interface and is used to recognize messages broadcasted between servers
func (s *Service) Process(msg *network.Envelope) {
	if msg.MsgType.Equal(msgTypes.msgSurveyCreationQuery) {
		tmp := (msg.Msg).(*SurveyCreationQuery)
		s.HandleSurveyCreationQuery(tmp)
	} else if msg.MsgType.Equal(msgTypes.msgSurveyResponseSharing) {
		tmp := (msg.Msg).(SurveyResponseSharing)
		s.HandleSurveyResponseSharing(&tmp)
	} else if msg.MsgType.Equal(msgTypes.msgSurveyFinalResponseSharing) {
		tmp := (msg.Msg).(SurveyFinalResponseSharing)
		s.HandleSurveyFinalResponseSharing(&tmp)
	} else if msg.MsgType.Equal(msgTypes.msgSurveyResultsQuery) {
		tmp := (msg.Msg).(*SurveyResultsQuery)
		s.HandleSurveyResultsQuery(tmp)
	} else if msg.MsgType.Equal(msgTypes.msgDDTfinished) {
		tmp := (msg.Msg).(*DDTfinished)
		s.HandleDDTfinished(tmp)
	}
}

// PushData is used to store incoming data by servers
func (s *Service) PushData(resp *SurveyResponseQuery) {
	for _, v := range resp.Responses {
		(s.survey[resp.SurveyID]).InsertClientResponse(v)
	}
	log.Lvl1(s.ServerIdentity(), " uploaded response data for survey ", resp.SurveyID)
}

// SendISMOthers sends a message to all other services
func (s *Service) SendISMOthers(el *onet.Roster, msg interface{}) error {
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

// Query Handlers
//______________________________________________________________________________________________________________________


// HandleSurveyCreationQuery handles the reception of a survey creation query by instantiating the corresponding survey.
// in the i2b2 case it will directly run the request response creation
func (s *Service) HandleSurveyCreationQuery(recq *SurveyCreationQuery) (network.Message, onet.ClientError) {

	s.appFlag = recq.AppFlag
	s.nbrLocalSurveys++
	s.nbrDPs = recq.NbrDPs[s.ServerIdentity().String()]

	log.LLvl1(s.ServerIdentity().String(), " received a Survey Creation Query")

	handlingServer := false

	if *recq.SurveyGenID == "" || *recq.SurveyID == "" {
		// if this server is the one receiving the query from the client
		newID := lib.SurveyID(uuid.NewV4().String())
		recq.SurveyID = &newID
		log.Lvl1(s.ServerIdentity().String(), " handles this new survey ", *recq.SurveyID, " ", *recq.SurveyGenID)
		if recq.DataToProcess == nil {
			// Unlynx
			recq.SurveyGenID = &newID

		} else {
			// P2D2i2b2
			handlingServer = true
		}
		// broadcasts the query
		err := s.SendISMOthers(&recq.Roster, recq)
		if err != nil {
			log.Error("broadcasting error ", err)
		}
		log.Lvl1(s.ServerIdentity(), " initiated the survey ", newID)

	}

	// chooses an ephemeral secret for this survey
	surveySecret := network.Suite.Scalar().Pick(random.Stream)

	// prepares the precomputation in case of shuffling
	lineSize := int(recq.SurveyDescription.AggregatingAttributesCount) + int(recq.SurveyDescription.GroupingAttributesEncCount)
	var precomputeShuffle []lib.CipherVectorScalar
	if recq.SurveyDescription.GroupingAttributesEncCount > 0 {
		//only needed if shuffling needed
		precomputeShuffle = precomputationWritingForShuffling(s.appFlag, s.ServerIdentity().String(), *recq.SurveyID, surveySecret, recq.Roster.Aggregate, lineSize)
	}

	// survey instantiation
	(s.survey[*recq.SurveyID]) = lib.Survey{
		Store:              lib.NewStore(),
		GenID:              *recq.SurveyGenID,
		ID:                 *recq.SurveyID,
		Roster:             recq.Roster,
		SurveySecretKey:    surveySecret,
		ClientPublic:       recq.ClientPubKey,
		SurveyDescription:  recq.SurveyDescription,
		Proofs:             recq.Proofs,
		ShufflePrecompute:  precomputeShuffle,
		SurveyQuerySubject: recq.QuerySubject,
		DataToProcess:      recq.DataToProcess,
		NbrDPs:             recq.NbrDPs,
		ExecutionMode:      recq.AggregationTotal,
		Sender:             s.ServerIdentity().ID,
	}

	// server is currently handling this survey
	s.mutex.Lock()
	s.current = *recq.SurveyID
	s.mutex.Unlock()

	log.Lvl1(s.ServerIdentity(), " created the survey ", *recq.SurveyID)
	log.Lvl1(s.ServerIdentity(), " has a list of ", len(s.survey), " survey(s)")

	if s.appFlag {
		if recq.DataToProcess == nil {
			// Unlynx
			testData := data.ReadDataFromFile(testDataFile)
			resp := EncryptDataToSurvey(s.ServerIdentity().String(), *recq.SurveyID, testData[strconv.Itoa(0)], recq.Roster.Aggregate, 1)
			s.PushData(resp)
		} else {
			//P2D2i2b2
			msg, err := s.HandleI2b2Query(recq, handlingServer)
			return msg, onet.NewClientError(err)
		}
	}

	// update surveyChannel so that the server knows he can start to process data from DPs
	s.surveyChannel <- 1
	return &ServiceResponse{*recq.SurveyID}, nil
}

// HandleSurveyResponseSharing handles reception of initial results in i2b2 query case
func (s *Service) HandleSurveyResponseSharing(resp *SurveyResponseSharing) (network.Message, onet.ClientError) {
	s.surveyCounter[resp.Survey.GenID]++
	s.surveyWithResponses[resp.Survey.ID] = resp.Survey
	log.LLvl1(s.ServerIdentity(), " gets a survey response for ", resp.Survey.GenID, " from ", s.ServerIdentity().ID)
	log.LLvl1(s.ServerIdentity(), " now has ", len(s.surveyWithResponses), " surveys with response(s)")

	//if it is the last survey result needed then unblock the channel
	if s.surveyCounter[resp.Survey.GenID] == addDPsNbr(resp.Survey.NbrDPs) {
		s.sharingResponsesChannel <- 1
	}

	return &ServiceResponse{SurveyID: resp.Survey.ID}, nil
}

func addDPsNbr(mp map[string]int64) int {
	result := 0
	for _, v := range mp {
		result = result + int(v)
	}
	return result
}

// HandleSurveyFinalResponseSharing handles reception of final shuffled results in i2b2 query case
func (s *Service) HandleSurveyFinalResponseSharing(resp *SurveyFinalResponseSharing) (network.Message, onet.ClientError) {
	log.LLvl1(s.ServerIdentity(), " gets a final survey response for from ", s.ServerIdentity().ID)
	s.finalResponses = resp.Responses
	// this is received only once and then the channel is unblocked to proceed to last step
	s.sharingFinalResponsesChannel <- 1
	return &ServiceResponse{"1"}, nil
}

// HandleSurveyResponseQuery handles a survey answers submission by a subject.
func (s *Service) HandleSurveyResponseQuery(resp *SurveyResponseQuery) (network.Message, onet.ClientError) {
	<-s.surveyChannel
	if s.survey[resp.SurveyID].ID == resp.SurveyID {
		s.PushData(resp)

		//unblock the channel to allow another DP to send its data
		s.surveyChannel <- 1
		//number of data providers who have already pushed the data
		s.dpChannel <- 1
		return &ServiceResponse{"1"}, nil
	}

	log.Lvl1(s.ServerIdentity(), " does not know about this survey!")
	return &ServiceResponse{resp.SurveyID}, nil
}

// HandleGetSurveyResultsQuery handles the survey result query by the surveyor.
func (s *Service) HandleSurveyResultsQuery(resq *SurveyResultsQuery) (network.Message, onet.ClientError) {

	log.Lvl1(s.ServerIdentity(), " received a survey result query")
	tmp := s.survey[resq.SurveyID]
	tmp.ClientPublic = resq.ClientPublic
	s.survey[resq.SurveyID] = tmp

	if resq.IntraMessage==false{
		resq.IntraMessage=true;

		err := s.SendISMOthers(&tmp.Roster, resq)
		if err != nil {
			log.Error("broadcasting error ", err)
		}
		s.StartService(resq.SurveyID,true)

		<-s.EndService
		log.Lvl1(s.ServerIdentity(), " completed the query processing...")

		return &SurveyResultResponse{Results: s.survey[resq.SurveyID].PullDeliverableResults()}, nil
	} else {
		s.StartService(resq.SurveyID,false)
		return nil, nil
	}
}

// HandleI2b2Query used to respond to an i2b2 query
func (s *Service) HandleI2b2Query(recq *SurveyCreationQuery, handlingServer bool) (network.Message, error) {
	// if server is responsible for this survey
	if handlingServer {
		allData := append(recq.QuerySubject, recq.DataToProcess...)

		// store data (skip unlynx shuffling)
		(s.survey[*recq.SurveyID]).PushShuffledClientResponses(allData)

		//ready to proceed to next steps
		s.surveyChannel <- 1

		// i2b2 compliant pipeline protocol
		pi, _ := s.StartProtocol(protocols.MedcoServiceProtocolName, *recq.SurveyID)
		<-pi.(*protocols.PipelineProtocol).FeedbackChannel

		// get aggregation results
		responses := (s.survey[*recq.SurveyID]).PullCothorityAggregatedClientResponses(false, lib.CipherText{})

		// mode 0
		if (s.survey[*recq.SurveyID]).ExecutionMode == 0 {
			return s.HandleI2b2QueryMode0(recq, responses)
		}

		//update survey responses with result
		tmp := s.survey[*recq.SurveyID]
		tmp.SurveyResponses = responses

		// list the survey in a list of answered surveys
		s.surveyWithResponses[*recq.SurveyID] = tmp
		s.surveyCounter[*recq.SurveyGenID]++

		log.LLvl1(s.ServerIdentity(), " added one survey to ", *recq.SurveyGenID)
		log.LLvl1(s.ServerIdentity(), " has ", s.surveyCounter[*recq.SurveyGenID], "  surveys with id ", *recq.SurveyGenID)

		// if this survey was the last for a query, then unblock the channel
		if len(s.surveyWithResponses) == addDPsNbr(recq.NbrDPs) {
			s.sharingResponsesChannel <- 1
			log.LLvl1(s.ServerIdentity(), " added last survey ", *recq.SurveyID, " to list of ", *recq.SurveyGenID)
		}

		//server sends the computed result
		log.LLvl1(s.ServerIdentity(), " sends survey ", *recq.SurveyID, " to all servers")

		err := s.SendISMOthers(&recq.Roster, &SurveyResponseSharing{Survey: s.surveyWithResponses[*recq.SurveyID]})
		if err != nil {
			log.Error("broadcasting error ", err)
		}

		//wait to have one response per data pro
		log.LLvl1(s.ServerIdentity(), " waits on ", *recq.SurveyGenID, " to complete execution of ", *recq.SurveyID)
		<-s.sharingResponsesChannel

		//if server (service) handles multiple survey, need to resend on channel
		//TODO unsure about this
		for s.nbrLocalSurveys > 1 {
			log.LLvl1(s.ServerIdentity(), " have multiple surveys to handle for ", *recq.SurveyGenID, " and currently handling ", *recq.SurveyID)
			s.sharingResponsesChannel <- 1
			s.nbrLocalSurveys--
		}

		// mode 1
		if (s.survey[*recq.SurveyID]).ExecutionMode == 1 {
			return s.HandleI2b2QueryMode1(recq, responses)
		}

		// mode 2
		return s.HandleI2b2QueryMode2(recq, responses)
	}

	// if not responsible for this survey
	s.surveyChannel <- 1
	return &ServiceResponse{SurveyID: *recq.SurveyID}, nil
}

// HandleI2b2QueryMode0 means each data provider gets its own result
func (s *Service) HandleI2b2QueryMode0(recq *SurveyCreationQuery, responses []lib.ClientResponse) (network.Message, error) {
	log.LLvl1(s.ServerIdentity(), " uses mode 0 for survey ", *recq.SurveyID)
	tmp := s.survey[*recq.SurveyID]
	tmp.SurveyResponses = responses
	tmp.Final = true
	s.survey[*recq.SurveyID] = tmp

	s.KeySwitchingPhase(*recq.SurveyID)
	responses = s.survey[*recq.SurveyID].PullDeliverableResults()
	return &SurveyResultResponse{Results: responses}, nil
}

// HandleI2b2QueryMode1 is for i2b2 total aggregation
func (s *Service) HandleI2b2QueryMode1(recq *SurveyCreationQuery, responses []lib.ClientResponse) (network.Message, error) {
	log.LLvl1(s.ServerIdentity(), " proceeds on ", *recq.SurveyID, " with mode 1 ")

	// compute total aggregation
	cl := lib.NewClientResponse(len(responses[0].ProbaGroupingAttributesEnc), len(responses[0].AggregatingAttributes))
	for _, v := range s.surveyWithResponses {
		if v.GenID == *recq.SurveyGenID {
			log.LLvl1(s.ServerIdentity(), " adds survey responses ", v.SurveyResponses[0].AggregatingAttributes)
			cl.AggregatingAttributes.Add(cl.AggregatingAttributes, v.SurveyResponses[0].AggregatingAttributes)
		}
	}

	//update survey state
	responses = []lib.ClientResponse{cl}
	tmp := s.survey[*recq.SurveyID]
	tmp.SurveyResponses = responses
	tmp.Final = true
	s.survey[*recq.SurveyID] = tmp

	//each server runs key switching on his result
	log.LLvl1(s.ServerIdentity(), " run key switching on ", *recq.SurveyID)
	s.KeySwitchingPhase(*recq.SurveyID)
	responses = s.survey[*recq.SurveyID].PullDeliverableResults()

	//update survey state
	tmp = s.survey[*recq.SurveyID]
	tmp.Final = false
	s.survey[*recq.SurveyID] = tmp

	return &SurveyResultResponse{Results: responses}, nil
}

// HandleI2b2QueryMode2 is for i2b2 shuffle
func (s *Service) HandleI2b2QueryMode2(recq *SurveyCreationQuery, responses []lib.ClientResponse) (network.Message, error) {
	log.LLvl1(s.ServerIdentity(), " proceeds on ", *recq.SurveyID, " with mode 2 ")

	// if the server is root server --> responsible for shuffling
	if reflect.DeepEqual(s.ServerIdentity().ID, s.survey[*recq.SurveyID].Roster.List[0].ID) {
		s.finalShufflingAndKeySwitching(recq, responses)
	}

	//received final shuffled list
	log.LLvl1(s.ServerIdentity(), " handling ", *recq.SurveyID, "is waiting for final response")
	<-s.sharingFinalResponsesChannel

	//choose the one with your id,
	//TODO do not work when server has multi DPs
	for _, v := range s.finalResponses {
		if v.ID == s.survey[*recq.SurveyID].Sender && !s.responseAlreadySent(v) {
			s.sentResponses = append(s.sentResponses, v)
			tmp := s.survey[*recq.SurveyID]
			tmp.SurveyResponses = []lib.ClientResponse{v.CR}
			tmp.Final = true
			s.survey[*recq.SurveyID] = tmp
			log.LLvl1(s.ServerIdentity(), " sends final response for ", *recq.SurveyID)
			return &SurveyResultResponse{Results: s.survey[*recq.SurveyID].SurveyResponses}, nil
		}

	}

	log.LLvl1(s.ServerIdentity(), " sends final response for ", *recq.SurveyID)
	return &SurveyResultResponse{}, nil
}

func (s *Service) HandleDDTfinished(recq *DDTfinished) (network.Message, onet.ClientError) {
	s.DDTChannel <- 1
	return nil,nil
}

// Protocol Handlers
//______________________________________________________________________________________________________________________

// NewProtocol creates a protocol instance executed by all nodes
func (s *Service) NewProtocol(tn *onet.TreeNodeInstance, conf *onet.GenericConfig) (onet.ProtocolInstance, error) {
	s.mutex.Lock()
	target := s.current
	s.mutex.Unlock()

	var pi onet.ProtocolInstance
	var err error

	switch tn.ProtocolName() {
		case protocols.ShufflingProtocolName:
			aux := s.survey[target].Final
			if aux {
				// i2b2 case
				log.LLvl1(s.ServerIdentity(), " starts a final shuffling protocol for survey ", target)
				pi, err = protocols.NewShufflingProtocol(tn)
				if (err != nil) {
					return nil, err
				}

				shuffle := pi.(*protocols.ShufflingProtocol)

				shuffle.Proofs = s.survey[target].Proofs
				aux := s.survey[target].SurveyResponses
				shuffle.TargetOfShuffle = &aux
			} else {
				// Unlynx
				pi, err = protocols.NewShufflingProtocol(tn)
				if (err != nil) {
					return nil, err
				}

				shuffle := pi.(*protocols.ShufflingProtocol)

				shuffle.Proofs = s.survey[target].Proofs
				shuffle.Precomputed = s.survey[target].ShufflePrecompute
				if tn.IsRoot() {
					clientResponses := s.survey[target].PullClientResponses()
					shuffle.TargetOfShuffle = &clientResponses
				}
			}
		case protocols.DeterministicTaggingProtocolName:
			pi, err = protocols.NewDeterministicTaggingProtocol(tn)
			if (err != nil) {
				return nil, err
			}
			hashCreation := pi.(*protocols.DeterministicTaggingProtocol)

			aux := s.survey[target].SurveySecretKey
			hashCreation.SurveySecretKey = &aux
			hashCreation.Proofs = s.survey[target].Proofs
			if tn.IsRoot() {
				shuffledClientResponses := s.survey[target].PullShuffledClientResponses()
				hashCreation.TargetOfSwitch = &shuffledClientResponses
			}
		case protocols.CollectiveAggregationProtocolName:
			pi, err = protocols.NewCollectiveAggregationProtocol(tn)
			if (err != nil) {
				return nil, err
			}

			groupedData := s.survey[target].PullLocallyAggregatedResponses()
			pi.(*protocols.CollectiveAggregationProtocol).GroupedData = &groupedData
			pi.(*protocols.CollectiveAggregationProtocol).Proofs = s.survey[target].Proofs

			// waits for all other nodes to finish the tagging phase
			counter := len(tn.Roster().List)-1
			for counter > 0 {
				counter = counter - (<-s.DDTChannel)
			}
		case protocols.KeySwitchingProtocolName:
			pi, err = protocols.NewKeySwitchingProtocol(tn)
			if (err != nil) {
				return nil, err
			}

			keySwitch := pi.(*protocols.KeySwitchingProtocol)
			keySwitch.Proofs = s.survey[target].Proofs

			if tn.IsRoot() {
				coaggr := []lib.ClientResponse{}
				aux := s.survey[target].Final
				if aux {
					//if key switching in i2b2 case
					coaggr = s.survey[target].SurveyResponses
				} else {
					//Unlynx
					if lib.DIFFPRI==true{
						coaggr = s.survey[target].PullCothorityAggregatedClientResponses(true, s.noise)
					}else {
						coaggr = s.survey[target].PullCothorityAggregatedClientResponses(false, lib.CipherText{})
					}
				}
				keySwitch.TargetOfSwitch = &coaggr
				tmp := s.survey[target].ClientPublic
				keySwitch.TargetPublicKey = &tmp
			}
		default:
			return nil, errors.New("Service attempts to start an unknown protocol: " + tn.ProtocolName() + ".")
	}

	return pi, nil
}

// NewDROProtocol implements the DRO protocol - shuffling the noise list
func (s *Service) NewDROProtocol(tn *onet.TreeNodeInstance)(onet.ProtocolInstance, error){
	pi, err := protocols.NewShufflingProtocol(tn)
	if err != nil{
		return nil, err
	}
	shuffle := pi.(*protocols.ShufflingProtocol)
	shuffle.Proofs = true
	shuffle.Precomputed = nil

	if tn.IsRoot() {
		clientResponses := make([]lib.ClientResponse, 0)
		noiseArray := generateNoiseValues(1000)
		for _, v := range noiseArray {
			clientResponses = append(clientResponses, lib.ClientResponse{GroupingAttributesClear: "", ProbaGroupingAttributesEnc: nil, AggregatingAttributes: *lib.EncryptIntVector(s.survey[s.current].Roster.Aggregate, []int64{v})})
		}
		shuffle.TargetOfShuffle = &clientResponses
	}
	return pi, nil
}

// StartProtocol starts a specific protocol (Pipeline, Shuffling, etc.)
func (s *Service) StartProtocol(name string, targetSurvey lib.SurveyID) (onet.ProtocolInstance, error) {
	tmp := s.survey[targetSurvey]
	tree := tmp.Roster.GenerateNaryTreeWithRoot(2, s.ServerIdentity())

	var tn *onet.TreeNodeInstance
	tn = s.NewTreeNodeInstance(tree, tree.Root, name)

	s.survey[targetSurvey] = tmp

	pi, err := s.NewProtocol(tn, nil)

	s.RegisterProtocolInstance(pi)
	go pi.Dispatch()
	go pi.Start()

	return pi, err
}


// Service Phases
//______________________________________________________________________________________________________________________

// StartService starts the service (with all its different steps/protocols)
func (s *Service) StartService(targetSurvey lib.SurveyID, root bool) error {

	log.Lvl1(s.ServerIdentity(), " is waiting on channel")
	<-s.surveyChannel

	counter := s.nbrDPs
	for counter > int64(0) {
		log.Lvl1(s.ServerIdentity(), " is waiting for ", counter, " data providers to send their data")
		counter = counter - int64(<-s.dpChannel)
	}
	log.LLvl1("All data providers (", s.nbrDPs, ") for server ", s.ServerIdentity(), " have sent their data")

	log.LLvl1(s.ServerIdentity(), " starts a Pipeline Protocol for survey ", targetSurvey)
	tmp := s.survey[targetSurvey]
	s.TargetSurvey = &tmp
	s.Proofs = s.survey[targetSurvey].Proofs

	// Normal Unlynx
	if s.TargetSurvey.DataToProcess == nil {
		// Shuffling Phase
		start := lib.StartTimer(s.ServerIdentity().String() + "_ShufflingPhase")

		err := s.ShufflingPhase(s.TargetSurvey.ID)
		if err != nil {
			log.Fatal("Error in the Shuffling Phase")
		}

		lib.EndTimer(start)

		// Tagging Phase
		start = lib.StartTimer(s.ServerIdentity().String() + "_TaggingPhase")

		err = s.TaggingPhase(s.TargetSurvey.ID)
		if err != nil {
			log.Fatal("Error in the Tagging Phase")
		}

		// broadcasts the query to unlock waiting channel
		aux :=s.survey[targetSurvey].Roster
		err = s.SendISMOthers(&aux,&DDTfinished{})
		if err != nil {
			log.Error("broadcasting error ", err)
		}

		lib.EndTimer(start)

		// Aggregation Phase
		if root==true{
			start := lib.StartTimer(s.ServerIdentity().String() + "_AggregationPhase")

			err = s.AggregationPhase(s.TargetSurvey.ID)
			if err != nil {
				log.Fatal("Error in the Aggregation Phase")
			}

			lib.EndTimer(start)
		}

		// DRO Phase
		if root==true && lib.DIFFPRI==true {
			start := lib.StartTimer(s.ServerIdentity().String() + "_DROPhase")

			s.DROPhase(s.TargetSurvey.ID)

			lib.EndTimer(start)
		}

		// Key Switch Phase
		if root==true{
			start := lib.StartTimer(s.ServerIdentity().String() + "_KeySwitchingPhase")

			s.KeySwitchingPhase(s.TargetSurvey.ID)

			lib.EndTimer(start)
		}
		s.EndService <- 1
	// i2b2 Unlynx
	} else {
		if root==true {
			s.TaggingPhase(s.TargetSurvey.ID)
			s.AggregationPhase(s.TargetSurvey.ID)
		}
	}

	return nil;
}


// ShufflingPhase performs the shuffling of the ClientResponses
func (s *Service) ShufflingPhase(targetSurvey lib.SurveyID) error {
	if len(s.survey[targetSurvey].ClientResponses) == 0 {
		log.Lvl1(s.ServerIdentity(), " no data to shuffle")
		return nil
	}

	//check if clear grouping attributes --> no shuffling
	if len(s.survey[targetSurvey].ClientResponses[0].GroupingAttributesClear) != 0 {
		s.survey[targetSurvey].PushShuffledClientResponses(s.survey[targetSurvey].ClientResponses)
		log.Lvl1(s.ServerIdentity(), " no shuffle with clear data")
		return nil
	}

	pi, err := s.StartProtocol(protocols.ShufflingProtocolName, targetSurvey)
	if err != nil {
		return err
	}
	shufflingResult := <-pi.(*protocols.ShufflingProtocol).FeedbackChannel

	s.survey[targetSurvey].PushShuffledClientResponses(shufflingResult)

	return err
}

// TaggingPhase performs the private grouping on the currently collected data.
func (s *Service) TaggingPhase(targetSurvey lib.SurveyID) error {
	if len(s.survey[targetSurvey].ShuffledClientResponses) == 0 {
		log.LLvl1(s.ServerIdentity(), "  for survey ", s.survey[targetSurvey].ID, " has no data to det tag")
		return nil
	}

	//check if only clear grouping attributes --> no det tag
	if len(s.survey[targetSurvey].ShuffledClientResponses[0].ProbaGroupingAttributesEnc) == 0 {
		for _, v := range s.survey[targetSurvey].ShuffledClientResponses {
			newClientDetResp := []lib.ClientResponseDet{{CR: lib.ClientResponse{GroupingAttributesClear: v.GroupingAttributesClear, ProbaGroupingAttributesEnc: v.ProbaGroupingAttributesEnc, AggregatingAttributes: v.AggregatingAttributes}, DetTag: v.GroupingAttributesClear}}
			(s.survey[targetSurvey]).PushDeterministicClientResponses(newClientDetResp, s.ServerIdentity().String(), (s.survey[targetSurvey]).Proofs)
		}
		//mcs.survey[targetSurvey].PushDeterministicClientResponses(mcs.survey[targetSurvey].ShuffledClientResponses, mcs.ServerIdentity().String(), mcs.survey[targetSurvey].Proofs)
		log.Lvl1(s.ServerIdentity(), " no det tag with only clear data")
		return nil
	}

	pi, err := s.StartProtocol(protocols.DeterministicTaggingProtocolName, targetSurvey)
	if err != nil {
		return err
	}
	deterministicTaggingResult := <-pi.(*protocols.DeterministicTaggingProtocol).FeedbackChannel

	// filters responses if i2b2 query
	if s.survey[targetSurvey].DataToProcess != nil {
		//P2D2i2b2
		grpToKeep := make(map[lib.GroupingKey]struct{}, 0)
		clientResponseToKeep := make([]lib.ClientResponseDet, 0)
		for i := 0; i < len(s.survey[targetSurvey].SurveyQuerySubject); i++ {
			grpToKeep[deterministicTaggingResult[i].DetTag] = struct{}{}
		}

		for _, v := range deterministicTaggingResult[len(s.survey[targetSurvey].SurveyQuerySubject):] {
			if _, ok := grpToKeep[v.DetTag]; ok {
				clientResponseToKeep = append(clientResponseToKeep, v)
			}
		}
		deterministicTaggingResult = clientResponseToKeep
		log.LLvl1(s.ServerIdentity(), " filtered out responses and kept: ", len(clientResponseToKeep), " valid ones")
	}
	s.survey[targetSurvey].PushDeterministicClientResponses(deterministicTaggingResult, s.ServerIdentity().String(), s.survey[targetSurvey].Proofs)
	return err
}

// AggregationPhase performs the per-group aggregation on the currently grouped data.
func (s *Service) AggregationPhase(targetSurvey lib.SurveyID) error {

	if s.survey[targetSurvey].DataToProcess == nil {
		//Unlynx
		pi, err := s.StartProtocol(protocols.CollectiveAggregationProtocolName, targetSurvey)
		if err != nil {
			return err
		}
		cothorityAggregatedData := <-pi.(*protocols.CollectiveAggregationProtocol).FeedbackChannel
		s.survey[targetSurvey].PushCothorityAggregatedClientResponses(cothorityAggregatedData.GroupedData)

	} else {
		//P2D2i2b2
		groupedData := s.survey[targetSurvey].PullLocallyAggregatedResponses()
		log.LLvl1(s.ServerIdentity(), " has ", len(groupedData), " responses to aggregate")
		clientRespFinal := lib.ClientResponse{}
		var dummyHash lib.GroupingKey
		first := true
		for i, v := range groupedData {
			if first {
				dummyHash = i
				first = false
			}
			if len(clientRespFinal.AggregatingAttributes) == 0 {
				clientRespFinal = v
			} else {
				clientRespFinal.Add(clientRespFinal, v)
			}

		}
		clientResponseToKeep := make(map[lib.GroupingKey]lib.ClientResponse, 0)
		clientResponseToKeep[dummyHash] = clientRespFinal
		s.survey[targetSurvey].PushCothorityAggregatedClientResponses(clientResponseToKeep)
	}

	return nil
}

// DROPhase shuffles the list of noise values.
func (s *Service) DROPhase(targetSurvey lib.SurveyID) error {
	tmp := s.survey[targetSurvey]
	tree := tmp.Roster.GenerateNaryTreeWithRoot(2, s.ServerIdentity())

	pi, err := s.CreateProtocol("DROInService", tree)
	if err != nil {
		return err
	}
	go pi.Start()

	shufflingResult := <-pi.(*protocols.ShufflingProtocol).FeedbackChannel
	s.noise = shufflingResult[0].AggregatingAttributes[0]

	return nil
}

// KeySwitchingPhase performs the switch to the querier's key on the currently aggregated data.
func (s *Service) KeySwitchingPhase(targetSurvey lib.SurveyID) error {

	pi, err := s.StartProtocol(protocols.KeySwitchingProtocolName, targetSurvey)
	if err != nil {
		return err
	}
	keySwitchedAggregatedResponses := <-pi.(*protocols.KeySwitchingProtocol).FeedbackChannel
	s.survey[targetSurvey].PushQuerierKeyEncryptedResponses(keySwitchedAggregatedResponses)
	return err
}

// Other Stuff.... (related with the protocols)
//______________________________________________________________________________________________________________________

// generateNoiseValues generates a number of n noise values from a given probabilistic distribution
func generateNoiseValues(n int) []int64 {

	//just for testing
	example := [...]int64{-4, -3, -2, -2, -1, -1, -1, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 3, 4}
	noise := make([]int64, 0)

	for i := 0; i < n; i++ {
		noise = append(noise, example[i%len(example)])
	}
	return noise
}

func precomputeForShuffling(serverName string, surveyID lib.SurveyID, surveySecret abstract.Scalar, collectiveKey abstract.Point, lineSize int) []lib.CipherVectorScalar {
	//log.Lvl1(serverName, " precomputes for shuffling of survey ", surveyID)
	precomputeShuffle := lib.CreatePrecomputedRandomize(network.Suite.Point().Base(), collectiveKey, network.Suite.Cipher(surveySecret.Bytes()), lineSize*2, 10)

	encoded, err := data.EncodeCipherVectorScalar(precomputeShuffle)

	if err != nil {
		log.Fatal("Error during marshaling")
	}
	data.WriteToGobFile(gobFile, encoded)

	return precomputeShuffle
}

func precomputationWritingForShuffling(appFlag bool, serverName string, surveyID lib.SurveyID, surveySecret abstract.Scalar, collectiveKey abstract.Point, lineSize int) []lib.CipherVectorScalar {
	//log.Lvl1(serverName, " precomputes for shuffling of survey ", surveyID)
	precomputeShuffle := []lib.CipherVectorScalar{}
	if appFlag {
		if _, err := os.Stat(gobFile); os.IsNotExist(err) {

			precomputeForShuffling(serverName, surveyID, surveySecret, collectiveKey, lineSize)
		} else {
			var encoded []lib.CipherVectorScalarBytes
			data.ReadFromGobFile(gobFile, &encoded)

			precomputeShuffle, err = data.DecodeCipherVectorScalar(encoded)

			if len(precomputeShuffle[0].CipherV) < lineSize {

			}
			if err != nil {
				log.Fatal("Error during unmarshaling")
			}
		}
	} else {
		precomputeShuffle = lib.CreatePrecomputedRandomize(network.Suite.Point().Base(), collectiveKey, network.Suite.Cipher(surveySecret.Bytes()), lineSize*2, 10)
	}
	return precomputeShuffle
}

func (s *Service) finalShufflingAndKeySwitching(recq *SurveyCreationQuery, responses []lib.ClientResponse) {
	listToShuffleIds := make([]FinalResponsesIds, 0)
	listToShuffle := make([]lib.ClientResponse, 0)

	log.LLvl1(s.ServerIdentity(), " shuffles final results of ", *recq.SurveyGenID, " (while handling ", *recq.SurveyID, ")")
	//construct list of responses --> shuffling
	for _, v := range s.surveyWithResponses {
		if v.GenID == *recq.SurveyGenID {
			listToShuffleIds = append(listToShuffleIds, FinalResponsesIds{v.Sender, v.SurveyResponses[0]})
			listToShuffle = append(listToShuffle, v.SurveyResponses[0])
		}
	}
	//shuffling
	tmp := s.survey[*recq.SurveyID]
	tmp.Final = true
	tmp.SurveyResponses = listToShuffle
	s.survey[*recq.SurveyID] = tmp
	pi, err := s.StartProtocol(protocols.ShufflingProtocolName, tmp.ID)
	if err != nil {
		log.Error("protocol issue, ", err)
	}
	shufflingFinalResult := <-pi.(*protocols.ShufflingProtocol).FeedbackChannel

	//key switching
	tmp = s.survey[*recq.SurveyID]
	tmp.SurveyResponses = shufflingFinalResult
	tmp.Final = true
	s.survey[*recq.SurveyID] = tmp
	log.LLvl1(s.ServerIdentity(), " runs key switching on ", *recq.SurveyID)
	s.KeySwitchingPhase(*recq.SurveyID)
	responses = s.survey[*recq.SurveyID].PullDeliverableResults()

	//assign responses to server ids
	for i := range listToShuffleIds {
		listToShuffleIds[i].CR = responses[i]
	}

	// share new list of survey results
	log.LLvl1(s.ServerIdentity(), " sends final results of ", *recq.SurveyGenID, " (while handling ", *recq.SurveyID, ")")

	err = s.SendISMOthers(&recq.Roster, &SurveyFinalResponseSharing{Responses: listToShuffleIds})
	if err != nil {
		log.Error("broadcasting error ", err)
	}

	s.finalResponses = listToShuffleIds
	s.sharingFinalResponsesChannel <- 1
}

//TODO do not work as expected
func (s *Service) responseAlreadySent(responseToCheck FinalResponsesIds) bool {
	result := false
	for _, v := range s.sentResponses {
		if reflect.DeepEqual(v, responseToCheck) {
			result = true
		}
	}

	return result
}
