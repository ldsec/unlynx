package serviceI2B2

import (
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/crypto.v0/abstract"
	"github.com/JoaoAndreSa/MedCo/lib"
	"gopkg.in/dedis/onet.v1/network"
	"sync"
	"gopkg.in/dedis/onet.v1/log"
	"github.com/satori/go.uuid"
	"gopkg.in/dedis/crypto.v0/random"

	"github.com/JoaoAndreSa/MedCo/services"
	"github.com/JoaoAndreSa/MedCo/protocols"
	"github.com/btcsuite/goleveldb/leveldb/errors"
	"reflect"
)


/// ServiceName is the registered name for the medco service.
const ServiceName = "MedCoI2b2"

// DROProtocolName is the registered name for the medco service protocol.
const DROProtocolName = "DRO"

// SurveyID unique ID for each survey.
type SurveyID string

type SurveyDpQuery struct {
	SurveyGenID  *SurveyID
	SurveyID     *SurveyID
	Roster       onet.Roster
	ClientPubKey abstract.Point
	NbrDPs       map[string]int64
	Proofs       bool
	AppFlag      bool

	// query statement
	Sum       []string
	Count     bool
	Where     []lib.WhereQueryAttribute
	Predicate string
	GroupBy   []string
	DpData	  []lib.ProcessResponse
	QueryMode     	int64
	IntraMessage bool
}

// Survey represents a survey with the corresponding params
type Survey struct {
	*lib.Store
	Query             SurveyDpQuery
	SurveySecretKey   abstract.Scalar
	ShufflePrecompute []lib.CipherVectorScalar
	Sender 		  network.ServerIdentityID
	IntermediateResponses map[network.ServerIdentityID]lib.FilteredResponse
	FinalResponses []FinalResponsesIds
	ResponseSent 	[]FinalResponsesIds
}

// MsgTypes defines the Message Type ID for all the service's intra-messages.
type MsgTypes struct {
	msgSurveyDpQuery        network.MessageTypeID
	msgSurveyResponseSharing      network.MessageTypeID
	msgSurveyFinalResponseSharing network.MessageTypeID
}

var msgTypes = MsgTypes{}

func init() {
	onet.RegisterNewService(ServiceName, NewService)
	msgTypes.msgSurveyDpQuery = network.RegisterMessage(&SurveyDpQuery{})
	msgTypes.msgSurveyResponseSharing = network.RegisterMessage(&SurveyResponseSharing{})
	msgTypes.msgSurveyFinalResponseSharing = network.RegisterMessage(&SurveyFinalResponseSharing{})
	network.RegisterMessage(&ServiceResult{})
}

// ServiceState represents the service "state".
type ServiceState struct {
	SurveyID SurveyID
}

// ServiceResult will contain final results of a survey and be sent to querier.
type ServiceResult struct {
	Results []lib.FilteredResponse
}

type SurveyResponseSharing struct {
	SurveyGenID SurveyID
	ServerID    network.ServerIdentityID
	Response    lib.FilteredResponse
}

// SurveyFinalResponseSharing represents a message containing survey ids and responses (i2b2)
type SurveyFinalResponseSharing struct {
	SurveyGenID SurveyID
	Responses []FinalResponsesIds
}

// FinalResponsesIds represents a survey response and the corresponding server Id (i2b2)
type FinalResponsesIds struct {
	ID network.ServerIdentityID
	CR lib.FilteredResponse
}


// Service defines a service in medco with a survey.
type Service struct {
	*onet.ServiceProcessor

	survey        map[SurveyID]Survey
	targetSurvey  *Survey
	nbrDPs        int64 // Number of data providers associated with each server
	proofs        bool
	appFlag       bool
	surveyChannel chan int // To wait for the survey to be created before loading data
	intermediateChannel     chan int // To wait for all data to be read before starting medco service protocol
	finalChannel		chan int
	ddtChannel    chan int // To wait for all nodes to finish the tagging before continuing
	endService    chan int // To wait for the service to end
	noise         lib.CipherText
	mutex         sync.Mutex

}


// NewService constructor which registers the needed messages.
func NewService(c *onet.Context) onet.Service {
	newMedCoInstance := &Service{
		ServiceProcessor: onet.NewServiceProcessor(c),
		survey:           make(map[SurveyID]Survey, 0),
		surveyChannel:    make(chan int, 100),
		intermediateChannel:        make(chan int, 100),
		finalChannel:        make(chan int, 100),
		ddtChannel:       make(chan int, 100),
		endService:       make(chan int, 1),
	}
	if cerr := newMedCoInstance.RegisterHandler(newMedCoInstance.HandleSurveyDpQuery); cerr != nil {
		log.Fatal("Wrong Handler.", cerr)
	}

	if cerr := newMedCoInstance.RegisterHandler(newMedCoInstance.HandleSurveyResponseSharing); cerr != nil {
		log.Fatal("Wrong Handler.", cerr)
	}

	if cerr := newMedCoInstance.RegisterHandler(newMedCoInstance.HandleSurveyFinalResponseSharing); cerr != nil {
		log.Fatal("Wrong Handler.", cerr)
	}

	c.RegisterProcessor(newMedCoInstance, msgTypes.msgSurveyDpQuery)
	c.RegisterProcessor(newMedCoInstance, msgTypes.msgSurveyResponseSharing)
	c.RegisterProcessor(newMedCoInstance, msgTypes.msgSurveyFinalResponseSharing)
	return newMedCoInstance
}

// Process implements the processor interface and is used to recognize messages broadcasted between servers
func (s *Service) Process(msg *network.Envelope) {
	if msg.MsgType.Equal(msgTypes.msgSurveyDpQuery) {
		tmp := (msg.Msg).(*SurveyDpQuery)
		s.HandleSurveyDpQuery(tmp)
	} else if msg.MsgType.Equal(msgTypes.msgSurveyResponseSharing) {
		tmp := (msg.Msg).(*SurveyResponseSharing)
		s.HandleSurveyResponseSharing(tmp)
	} else if msg.MsgType.Equal(msgTypes.msgSurveyFinalResponseSharing) {
		tmp := (msg.Msg).(*SurveyFinalResponseSharing)
		s.HandleSurveyFinalResponseSharing(tmp)
	}
}

// HandleSurveyCreationQuery handles the reception of a survey creation query by instantiating the corresponding survey.
// in the i2b2 case it will directly run the request response creation
func (s *Service) HandleSurveyDpQuery(sdq *SurveyDpQuery) (network.Message, onet.ClientError) {

	s.appFlag = sdq.AppFlag
	//s.nbrLocalSurveys++
	s.nbrDPs = sdq.NbrDPs[s.ServerIdentity().String()]

	log.LLvl1(s.ServerIdentity().String(), " received a Survey Dp Query")


	surveySecret := network.Suite.Scalar().Pick(random.Stream)



	if !sdq.IntraMessage {
		sdq.IntraMessage = true
		// if this server is the one receiving the query from the client
		newID := SurveyID(uuid.NewV4().String())
		sdq.SurveyID = &newID
		log.Lvl1(s.ServerIdentity().String(), " handles this new survey ", *sdq.SurveyID, " ", *sdq.SurveyGenID)

		(s.survey[*sdq.SurveyID]) = Survey{
			Store:             lib.NewStore(),
			Query:             *sdq,
			SurveySecretKey:   surveySecret,
			//ShufflePrecompute: precomputeShuffle,
			Sender:            s.ServerIdentity().ID,
			IntermediateResponses: make(map[network.ServerIdentityID]lib.FilteredResponse),
		}
		log.LLvl1("AVANCE ", s.survey[*sdq.SurveyID])

		// broadcasts the query
		err := services.SendISMOthers(s.ServiceProcessor, &sdq.Roster, sdq)
		if err != nil {
			log.Error("broadcasting error ", err)
		}

		// skip Unlynx shuffling
		log.LLvl1(s.ServerIdentity(), " ", s.survey[*sdq.SurveyID])
		s.survey[*sdq.SurveyID].PushShuffledProcessResponses(sdq.DpData)
		s.StartServicePartOne(*sdq.SurveyID)

		<-s.endService

		r1 := s.survey[*sdq.SurveyID].PullCothorityAggregatedFilteredResponses(lib.DIFFPRI, s.noise)
		// add server identity in the sharing
		log.LLvl1(s.ServerIdentity(), " sends load of")
		err = services.SendISMOthers(s.ServiceProcessor, &sdq.Roster, &SurveyResponseSharing{*sdq.SurveyGenID, s.ServerIdentity().ID, r1[0]})
		if err != nil {
			log.Error("broadcasting error ", err)
		}

		s.mutex.Lock()
		log.LLvl1(s.survey[*sdq.SurveyGenID].IntermediateResponses)
		if s.survey[*sdq.SurveyGenID].IntermediateResponses == nil {
			tmp := s.survey[*sdq.SurveyGenID]
			tmp.IntermediateResponses = make(map[network.ServerIdentityID]lib.FilteredResponse)
			s.survey[*sdq.SurveyGenID] = tmp
		}

		s.survey[*sdq.SurveyGenID].IntermediateResponses[s.ServerIdentity().ID] =  r1[0]
		log.LLvl1(services.CountDps(sdq.NbrDPs))
		log.LLvl1(len(s.survey[*sdq.SurveyGenID].IntermediateResponses))
		s.mutex.Unlock()
		if int64(len(s.survey[*sdq.SurveyGenID].IntermediateResponses)) == services.CountDps(sdq.NbrDPs){
			log.LLvl1(s.ServerIdentity(), " LA")
			s.intermediateChannel <-1
		}
		log.LLvl1(s.ServerIdentity(), " COUCOU")
		<- s.intermediateChannel
		log.Lvl1(s.ServerIdentity(), " completed the first part")

		if s.ServerIdentity().ID == sdq.Roster.List[0].ID {
			log.LLvl1(s.ServerIdentity(), " executes part 2")

			tmp := s.survey[*sdq.SurveyGenID]
			tmp.Query = s.survey[*sdq.SurveyID].Query
			tmp.Store = s.survey[*sdq.SurveyID].Store
			s.survey[*sdq.SurveyGenID] = tmp

			s.StartServicePartTwo(*sdq.SurveyGenID)

			<-s.endService

			finalResponsesUnFormat := s.survey[*sdq.SurveyGenID].PullDeliverableResults()
			log.LLvl1(finalResponsesUnFormat)
			finalResponses := make([]FinalResponsesIds, len(finalResponsesUnFormat))
			counter := 0
			for i := range s.survey[*sdq.SurveyGenID].IntermediateResponses{
				finalResponses[counter].ID = i
				finalResponses[counter].CR = finalResponsesUnFormat[counter]
				counter = counter + 1
			}

			// broadcasts the final response
			err = services.SendISMOthers(s.ServiceProcessor, &sdq.Roster, &SurveyFinalResponseSharing{*sdq.SurveyGenID, finalResponses})
			if err != nil {
				log.Error("broadcasting error ", err)
			}

			tmp = s.survey[*sdq.SurveyGenID]
			tmp.FinalResponses = finalResponses
			s.survey[*sdq.SurveyGenID] = tmp
			s.finalChannel <- 1
		}

		<- s.finalChannel

		finalResult := []lib.FilteredResponse{}
		log.LLvl1(s.survey[*sdq.SurveyGenID].FinalResponses)
		for _,v := range s.survey[*sdq.SurveyGenID].FinalResponses{
			s.mutex.Lock()
			if v.ID == s.ServerIdentity().ID && !s.checkIfAlreadySent(v,*sdq.SurveyGenID){
				finalResult = []lib.FilteredResponse{v.CR}
				log.LLvl1(finalResult)
				tmp := s.survey[*sdq.SurveyGenID]
				tmp.ResponseSent = append(tmp.ResponseSent, v)
				s.survey[*sdq.SurveyGenID] = tmp
			}
			s.mutex.Unlock()
		}
		log.LLvl1(finalResult)
		return &ServiceResult{Results:finalResult}, nil


	}

	(s.survey[*sdq.SurveyID]) = Survey{
		Store:             lib.NewStore(),
		Query:             *sdq,
		SurveySecretKey:   surveySecret,
		//ShufflePrecompute: precomputeShuffle,
		Sender:            s.ServerIdentity().ID,
		IntermediateResponses: make(map[network.ServerIdentityID]lib.FilteredResponse,0),
	}
	log.LLvl1("AVANCE ", s.survey[*sdq.SurveyID])

	// chooses an ephemeral secret for this survey


	// prepares the precomputation in case of shuffling
	//lineSize := int(len(sdq.Sum)) + int(len(sdq.Where)) + int(len(sdq.GroupBy)) + 2 // + 1 is for the possible count attribute
	//precomputeShuffle := services.PrecomputationWritingForShuffling(s.appFlag, s.ServerIdentity().String(), *sdq.SurveyID, surveySecret, sdq.Roster.Aggregate, lineSize)

	// survey instantiation


	/*log.Lvl1(s.ServerIdentity(), " created the survey ", *sdq.SurveyID)
	log.Lvl1(s.ServerIdentity(), " has a list of ", len(s.survey), " survey(s)")

	if s.appFlag {
		//TODO: develop default and i2b2 app
	}
	msg, err := s.HandleI2b2Query(sdq, handlingServer)
	if err != nil {
		log.Error("handle i2b2 error ", err)
	}*/

	// update surveyChannel so that the server knows he can start to process data from DPs
	//s.surveyChannel <- 1
	return &ServiceResult{/*msg*/}, nil
}

// StartServicePartOne starts the service (with all its different steps/protocols)
func (s *Service) StartServicePartOne(targetSurvey SurveyID) error {

	log.LLvl1(s.ServerIdentity(), " starts a Medco Protocol for survey ", targetSurvey)
	tmp := s.survey[targetSurvey]
	s.targetSurvey = &tmp
	s.proofs = s.survey[targetSurvey].Query.Proofs

	// Tagging Phase
	start := lib.StartTimer(s.ServerIdentity().String() + "_TaggingPhase")

	err := s.TaggingPhase(*s.targetSurvey.Query.SurveyID)
	if err != nil {
		log.Fatal("Error in the Tagging Phase")
	}

	lib.EndTimer(start)

	//skip collective aggregation
	s.survey[targetSurvey].PushCothorityAggregatedFilteredResponses(s.survey[targetSurvey].PullLocallyAggregatedResponses())

	// DRO Phase
	if lib.DIFFPRI == true {
		start := lib.StartTimer(s.ServerIdentity().String() + "_DROPhase")

		s.DROPhase(*s.targetSurvey.Query.SurveyID)

		lib.EndTimer(start)
	}

	s.endService <- 1
	return nil
}

// StartServicePartOne starts the service (with all its different steps/protocols)
func (s *Service) StartServicePartTwo(targetSurvey SurveyID) error {

	log.LLvl1(s.ServerIdentity(), " starts a Medco Protocol for survey ", targetSurvey)
	tmp := s.survey[targetSurvey]
	s.targetSurvey = &tmp
	s.proofs = s.survey[targetSurvey].Query.Proofs

	// Tagging Phase
	start := lib.StartTimer(s.ServerIdentity().String() + "_TaggingPhase")

	//TODO put it in the new Protocol for survey
	err := s.ShufflingPhase(targetSurvey)
	if err != nil {
		log.Fatal("Error in the Tagging Phase")
	}

	lib.EndTimer(start)

	//skip collective aggregation
	shuffledFinalResponsesUnformat:= s.survey[targetSurvey].PullShuffledProcessResponses()

	shuffledFinalResponsesFormat := make([]lib.FilteredResponse, len(shuffledFinalResponsesUnformat))
	for i,v := range shuffledFinalResponsesUnformat{
		shuffledFinalResponsesFormat[i].GroupByEnc = v.GroupByEnc
		shuffledFinalResponsesFormat[i].AggregatingAttributes = v.AggregatingAttributes
	}

	// here we use the table to store the responses used in key switching
	s.survey[targetSurvey].PushQuerierKeyEncryptedResponses(shuffledFinalResponsesFormat)

	err = s.KeySwitchingPhase(*s.targetSurvey.Query.SurveyID)
	if err != nil {
		log.Fatal("Error in the Tagging Phase")
	}

	s.endService <- 1
	return nil
}

func (s *Service) checkIfAlreadySent(fri FinalResponsesIds, surveyID SurveyID) bool{
	result := false
	for _,v := range s.survey[surveyID].ResponseSent {
		if reflect.DeepEqual(fri, v){
			result = true
		}
	}
	return result
}

// TaggingPhase performs the private grouping on the currently collected data.
func (s *Service) TaggingPhase(targetSurvey SurveyID) error {
	if len(s.survey[targetSurvey].ShuffledProcessResponses) == 0 {
		log.LLvl1(s.ServerIdentity(), "  for survey ", s.survey[targetSurvey].Query.SurveyID, " has no data to det tag")
		return nil
	}

	pi, err := s.StartProtocol(protocols.DeterministicTaggingProtocolName, targetSurvey)
	if err != nil {
		return err
	}

	deterministicTaggingResult := <-pi.(*protocols.DeterministicTaggingProtocol).FeedbackChannel

	queryWhereTag := []lib.WhereQueryAttributeTagged{}
	for i, v := range deterministicTaggingResult[:len(s.survey[targetSurvey].Query.Where)] {
		newElem := lib.WhereQueryAttributeTagged{Name: s.survey[targetSurvey].Query.Where[i].Name, Value: v.DetTagWhere[0]}
		queryWhereTag = append(queryWhereTag, newElem)
	}
	deterministicTaggingResult = deterministicTaggingResult[len(s.survey[targetSurvey].Query.Where):]
	filteredResponses := services.FilterResponses(s.survey[targetSurvey].Query.Predicate, queryWhereTag, deterministicTaggingResult)
	s.survey[targetSurvey].PushDeterministicFilteredResponses(filteredResponses, s.ServerIdentity().String(), s.survey[targetSurvey].Query.Proofs)
	return err
}

// DROPhase shuffles the list of noise values.
func (s *Service) DROPhase(targetSurvey SurveyID) error {
	tmp := s.survey[targetSurvey]
	tree := tmp.Query.Roster.GenerateNaryTreeWithRoot(2, s.ServerIdentity())

	pi, err := s.CreateProtocol(DROProtocolName, tree)
	if err != nil {
		return err
	}
	go pi.Start()

	shufflingResult := <-pi.(*protocols.ShufflingProtocol).FeedbackChannel
	s.noise = shufflingResult[0].AggregatingAttributes[0]

	return nil
}

// ShufflingPhase performs the shuffling of the ClientResponses
func (s *Service) ShufflingPhase(targetSurvey SurveyID) error {
	/*if len(s.survey[targetSurvey].DpResponses) == 0 && len(s.survey[targetSurvey].DpResponsesAggr) == 0 {
		log.Lvl1(s.ServerIdentity(), " no data to shuffle")
		return nil
	}*/

	pi, err := s.StartProtocol(protocols.ShufflingProtocolName, targetSurvey)
	if err != nil {
		return err
	}
	shufflingResult := <-pi.(*protocols.ShufflingProtocol).FeedbackChannel

	s.survey[targetSurvey].PushShuffledProcessResponses(shufflingResult)
	return err
}

// StartProtocol starts a specific protocol (Pipeline, Shuffling, etc.)
func (s *Service) StartProtocol(name string, targetSurvey SurveyID) (onet.ProtocolInstance, error) {
	tmp := s.survey[targetSurvey]
	tree := tmp.Query.Roster.GenerateNaryTreeWithRoot(2, s.ServerIdentity())

	var tn *onet.TreeNodeInstance
	tn = s.NewTreeNodeInstance(tree, tree.Root, name)

	s.survey[targetSurvey] = tmp
	conf := onet.GenericConfig{Data: []byte(string(targetSurvey))}

	pi, err := s.NewProtocol(tn, &conf)

	s.RegisterProtocolInstance(pi)
	go pi.Dispatch()
	go pi.Start()

	return pi, err
}

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

		shuffle.Proofs = s.survey[target].Query.Proofs
		shuffle.Precomputed = s.survey[target].ShufflePrecompute
		if tn.IsRoot() {
			targetShuffle := []lib.ProcessResponse{}
			for _,v := range s.survey[target].IntermediateResponses{
				newProcessResponse := lib.ProcessResponse{GroupByEnc:v.GroupByEnc, AggregatingAttributes:v.AggregatingAttributes}
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

		aux := s.survey[target].SurveySecretKey
		hashCreation.SurveySecretKey = &aux
		hashCreation.Proofs = s.survey[target].Query.Proofs
		hashCreation.NbrQueryAttributes = len(s.survey[target].Query.Where)
		if tn.IsRoot() {
			shuffledClientResponses := s.survey[target].PullShuffledProcessResponses()
			queryWhereToTag := []lib.ProcessResponse{}
			for _, v := range s.survey[target].Query.Where {
				tmp := lib.CipherVector{v.Value}
				queryWhereToTag = append(queryWhereToTag, lib.ProcessResponse{WhereEnc: tmp, GroupByEnc: nil, AggregatingAttributes: nil})
			}
			shuffledClientResponses = append(queryWhereToTag, shuffledClientResponses...)
			hashCreation.TargetOfSwitch = &shuffledClientResponses

		}

	case protocols.CollectiveAggregationProtocolName:
		pi, err = protocols.NewCollectiveAggregationProtocol(tn)
		if err != nil {
			return nil, err
		}

		groupedData := s.survey[target].PullLocallyAggregatedResponses()
		pi.(*protocols.CollectiveAggregationProtocol).GroupedData = &groupedData
		pi.(*protocols.CollectiveAggregationProtocol).Proofs = s.survey[target].Query.Proofs

		// waits for all other nodes to finish the tagging phase
		counter := len(tn.Roster().List) - 1
		for counter > 0 {
			counter = counter - (<-s.ddtChannel)
		}

	case DROProtocolName:

	case protocols.KeySwitchingProtocolName:
		pi, err = protocols.NewKeySwitchingProtocol(tn)
		if err != nil {
			return nil, err
		}

		keySwitch := pi.(*protocols.KeySwitchingProtocol)
		keySwitch.Proofs = s.survey[target].Query.Proofs
		if tn.IsRoot() {
			coaggr := []lib.FilteredResponse{}

			if lib.DIFFPRI == true {
				//TODO add diff privacy in this case too
				coaggr = s.survey[target].PullDeliverableResults(/*true, s.noise*/)
			} else {
				coaggr = s.survey[target].PullDeliverableResults(/*false, lib.CipherText{}*/)
			}

			keySwitch.TargetOfSwitch = &coaggr
			tmp1 := s.survey[target].Query.ClientPubKey
			keySwitch.TargetPublicKey = &tmp1
		}
	default:
		return nil, errors.New("Service attempts to start an unknown protocol: " + tn.ProtocolName() + ".")
	}
	return pi, nil
}


// HandleSurveyResponseSharing handles reception of initial results in i2b2 query case
func (s *Service) HandleSurveyResponseSharing(resp *SurveyResponseSharing) (network.Message, onet.ClientError) {
	s.mutex.Lock()
	if s.survey[resp.SurveyGenID].IntermediateResponses == nil {
		tmp := s.survey[resp.SurveyGenID]
		tmp.IntermediateResponses = make(map[network.ServerIdentityID]lib.FilteredResponse)
		s.survey[resp.SurveyGenID] = tmp
	}
	s.survey[resp.SurveyGenID].IntermediateResponses[resp.ServerID] = resp.Response
	s.mutex.Unlock()
	log.LLvl1(s.ServerIdentity(), " gets a survey response for ", resp.SurveyGenID, " from ", resp.ServerID)
	log.LLvl1(s.ServerIdentity(), " now has ", len(s.survey[resp.SurveyGenID].IntermediateResponses), " surveys with response(s)")

	//if it is the last survey result needed then unblock the channel
	log.LLvl1(s.ServerIdentity(), " ", len(s.survey[resp.SurveyGenID].IntermediateResponses))
	if int64(len(s.survey[resp.SurveyGenID].IntermediateResponses)) == 3 {
		log.LLvl1(s.ServerIdentity(), " ICI")
		s.intermediateChannel <- 1
	}

	return &ServiceResult{}, nil
}

// KeySwitchingPhase performs the switch to the querier's key on the currently aggregated data.
func (s *Service) KeySwitchingPhase(targetSurvey SurveyID) error {
	pi, err := s.StartProtocol(protocols.KeySwitchingProtocolName, targetSurvey)
	if err != nil {
		return err
	}
	keySwitchedAggregatedResponses := <-pi.(*protocols.KeySwitchingProtocol).FeedbackChannel
	log.LLvl1(keySwitchedAggregatedResponses)
	s.survey[targetSurvey].PushQuerierKeyEncryptedResponses(keySwitchedAggregatedResponses)
	return err
}

// HandleSurveyFinalResponseSharing handles reception of final shuffled results in i2b2 query case
func (s *Service) HandleSurveyFinalResponseSharing(resp *SurveyFinalResponseSharing) (network.Message, onet.ClientError) {
	log.LLvl1(s.ServerIdentity(), " gets a final survey response for from ", s.ServerIdentity().ID)
	tmp := s.survey[resp.SurveyGenID]
	tmp.FinalResponses = resp.Responses
	s.survey[resp.SurveyGenID] = tmp
	// this is received only once and then the channel is unblocked to proceed to last step
	s.finalChannel <- 1
	return &ServiceResult{}, nil
}


/*
// HandleI2b2Query used to respond to an i2b2 query
func (s *Service) HandleI2b2Query(recq *SurveyDpQuery, handlingServer bool) (network.Message, error) {
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
}*/