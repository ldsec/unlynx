package servicesunlynx

import (
	"fmt"
	"strconv"
	"time"

	"github.com/Knetic/govaluate"
	"github.com/fanliao/go-concurrentMap"
	"github.com/ldsec/unlynx/data"
	"github.com/ldsec/unlynx/lib"
	"github.com/ldsec/unlynx/lib/aggregation"
	"github.com/ldsec/unlynx/lib/differential_privacy"
	"github.com/ldsec/unlynx/lib/key_switch"
	"github.com/ldsec/unlynx/lib/shuffle"
	"github.com/ldsec/unlynx/lib/store"
	"github.com/ldsec/unlynx/lib/tools"
	"github.com/ldsec/unlynx/protocols"
	"github.com/satori/go.uuid"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
	"go.dedis.ch/onet/v3/network"
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
	IntraMessage bool
	Source       *network.ServerIdentity

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
	ShufflePrecompute []libunlynxshuffle.CipherVectorScalar
	Lengths           [][]int
	TargetOfSwitch    []libunlynx.ProcessResponse

	// channels
	SurveyChannel chan int // To wait for the survey to be created before loading data
	DpChannel     chan int // To wait for all data to be read before starting unlynx service protocol
	DDTChannel    chan int // To wait for all nodes to finish the tagging before continuing

	Noise libunlynx.CipherText
}

// MsgTypes defines the Message Type ID for all the service's intra-messages.
type MsgTypes struct {
	msgSurveyCreationQuery    network.MessageTypeID
	msgSurveyResultsQuery     network.MessageTypeID
	msgDDTfinished            network.MessageTypeID
	msgQueryBroadcastFinished network.MessageTypeID
}

var msgTypes = MsgTypes{}

func init() {
	_, err := onet.RegisterNewService(ServiceName, NewService)
	log.ErrFatal(err)

	msgTypes.msgSurveyCreationQuery = network.RegisterMessage(&SurveyCreationQuery{})
	msgTypes.msgSurveyResultsQuery = network.RegisterMessage(&SurveyResultsQuery{})
	msgTypes.msgDDTfinished = network.RegisterMessage(&DDTfinished{})
	msgTypes.msgQueryBroadcastFinished = network.RegisterMessage(&QueryBroadcastFinished{})

	network.RegisterMessage(&SurveyResponseQuery{})
	network.RegisterMessage(&ServiceState{})
	network.RegisterMessage(&ServiceResult{})
}

// QueryBroadcastFinished is used to ensure that all servers have received the query/survey
type QueryBroadcastFinished struct {
	SurveyID SurveyID
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

func (s *Service) getSurvey(sid SurveyID) (Survey, error) {
	surv, err := s.Survey.Get(string(sid))
	if err != nil {
		return Survey{}, fmt.Errorf("error while getting surveyID "+string(sid)+": %v", err)
	}
	if surv == nil {
		return Survey{}, fmt.Errorf("empty map entry while getting surveyID " + string(sid))
	}
	return surv.(Survey), nil
}

func (s *Service) putSurvey(sid SurveyID, surv Survey) error {
	_, err := s.Survey.Put(string(sid), surv)
	return err
}

// NewService constructor which registers the needed messages.
func NewService(c *onet.Context) (onet.Service, error) {
	newUnLynxInstance := &Service{
		ServiceProcessor: onet.NewServiceProcessor(c),
		Survey:           concurrent.NewConcurrentMap(),
	}
	var cerr error
	if cerr = newUnLynxInstance.RegisterHandler(newUnLynxInstance.HandleSurveyCreationQuery); cerr != nil {
		return nil, fmt.Errorf("wrong Handler: %v", cerr)
	}
	if cerr = newUnLynxInstance.RegisterHandler(newUnLynxInstance.HandleSurveyResponseQuery); cerr != nil {
		return nil, fmt.Errorf("wrong Handler: %v", cerr)
	}
	if cerr = newUnLynxInstance.RegisterHandler(newUnLynxInstance.HandleSurveyResultsQuery); cerr != nil {
		return nil, fmt.Errorf("wrong Handler: %v", cerr)
	}
	if cerr = newUnLynxInstance.RegisterHandler(newUnLynxInstance.HandleDDTfinished); cerr != nil {
		return nil, fmt.Errorf("wrong Handler: %v", cerr)
	}
	if cerr = newUnLynxInstance.RegisterHandler(newUnLynxInstance.HandleQueryBroadcastFinished); cerr != nil {
		return nil, fmt.Errorf("wrong Handler: %v", cerr)
	}

	c.RegisterProcessor(newUnLynxInstance, msgTypes.msgSurveyCreationQuery)
	c.RegisterProcessor(newUnLynxInstance, msgTypes.msgSurveyResultsQuery)
	c.RegisterProcessor(newUnLynxInstance, msgTypes.msgDDTfinished)
	c.RegisterProcessor(newUnLynxInstance, msgTypes.msgQueryBroadcastFinished)
	return newUnLynxInstance, cerr
}

// Process implements the processor interface and is used to recognize messages broadcasted between servers
func (s *Service) Process(msg *network.Envelope) {
	if msg.MsgType.Equal(msgTypes.msgSurveyCreationQuery) {
		msgSurveyCreationQuery := (msg.Msg).(*SurveyCreationQuery)
		_, err := s.HandleSurveyCreationQuery(msgSurveyCreationQuery)
		if err != nil {
			log.Error(err)
		}
	} else if msg.MsgType.Equal(msgTypes.msgSurveyResultsQuery) {
		msgSurveyResultsQuery := (msg.Msg).(*SurveyResultsQuery)
		_, err := s.HandleSurveyResultsQuery(msgSurveyResultsQuery)
		if err != nil {
			log.Error(err)
		}
	} else if msg.MsgType.Equal(msgTypes.msgQueryBroadcastFinished) {
		msgQueryBroadcastFinished := (msg.Msg).(*QueryBroadcastFinished)
		_, err := s.HandleQueryBroadcastFinished(msgQueryBroadcastFinished)
		if err != nil {
			log.Error(err)
		}
	} else if msg.MsgType.Equal(msgTypes.msgDDTfinished) {
		msgDDTfinished := (msg.Msg).(*DDTfinished)
		_, err := s.HandleDDTfinished(msgDDTfinished)
		if err != nil {
			log.Error(err)
		}
	}
}

// PushData is used to store incoming data by servers
func (s *Service) PushData(resp *SurveyResponseQuery, proofs bool) error {
	survey, err := s.getSurvey(resp.SurveyID)
	if err != nil {
		return err
	}

	for _, v := range resp.Responses {
		dr := libunlynx.DpResponse{}
		if err := dr.FromDpResponseToSend(v); err != nil {
			return err
		}
		survey.InsertDpResponse(dr, proofs, survey.Query.GroupBy, survey.Query.Sum, survey.Query.Where)
	}
	err = s.putSurvey(resp.SurveyID, survey)
	if err != nil {
		return err
	}

	log.Lvl1(s.ServerIdentity(), " uploaded response data for survey ", resp.SurveyID)
	return nil
}

// Query Handlers
//______________________________________________________________________________________________________________________

// HandleSurveyCreationQuery handles the reception of a survey creation query by instantiating the corresponding survey.
func (s *Service) HandleSurveyCreationQuery(recq *SurveyCreationQuery) (network.Message, error) {
	log.Lvl1(s.ServerIdentity().String(), " received a Survey Creation Query")

	// if this server is the one receiving the query from the client
	if recq.IntraMessage == false {
		id := uuid.NewV4()
		newID := SurveyID(id.String())
		recq.SurveyID = newID
		log.Lvl1(s.ServerIdentity().String(), " handles this new survey ", recq.SurveyID)

	}

	// chooses an ephemeral secret for this survey
	surveySecret := libunlynx.SuiTe.Scalar().Pick(libunlynx.SuiTe.RandomStream())

	// prepares the precomputation for shuffling
	lineSize := int(len(recq.Sum)) + int(len(recq.Where)) + int(len(recq.GroupBy)) + 1 // + 1 is for the possible count attribute
	precomputeShuffle, err := libunlynxshuffle.PrecomputationWritingForShuffling(recq.AppFlag, gobFile, s.ServerIdentity().String(), surveySecret, recq.Roster.Aggregate, lineSize)
	if err != nil {
		return nil, err
	}

	// survey instantiation
	_, err = s.Survey.Put((string)(recq.SurveyID), Survey{
		Store:             libunlynxstore.NewStore(),
		Query:             *recq,
		SurveySecretKey:   surveySecret,
		ShufflePrecompute: precomputeShuffle,

		SurveyChannel: make(chan int, 100),
		DpChannel:     make(chan int, 100),
		DDTChannel:    make(chan int, 100),
	})
	if err != nil {
		return nil, err
	}
	log.Lvl1(s.ServerIdentity(), " initiated the survey ", recq.SurveyID)

	if recq.IntraMessage == false {
		recq.IntraMessage = true
		recq.Source = s.ServerIdentity()
		// broadcasts the query
		err := libunlynxtools.SendISMOthers(s.ServiceProcessor, &recq.Roster, recq)
		if err != nil {
			return nil, err
		}
		recq.IntraMessage = false
	} else {
		// warn 'root' node that it has received the query
		err := s.SendRaw(recq.Source, &QueryBroadcastFinished{SurveyID: recq.SurveyID})
		if err != nil {
			return nil, err
		}
	}

	// if it is a app download the data from the test file
	if recq.AppFlag {
		index := 0
		for index = 0; index < len(recq.Roster.List); index++ {
			if recq.Roster.List[index].String() == s.ServerIdentity().String() {
				break
			}
		}
		testData, err := dataunlynx.ReadDataFromFile("unlynx_test_data.txt")
		if err != nil {
			return nil, err
		}

		resp, err := EncryptDataToSurvey(s.ServerIdentity().String(), recq.SurveyID, testData[strconv.Itoa(index)], recq.Roster.Aggregate, 1, recq.Count)
		if err != nil {
			return nil, err
		}
		err = s.PushData(resp, recq.Proofs)
		if err != nil {
			return nil, err
		}

		//number of data providers who have already pushed the data
		survey, err := s.getSurvey(resp.SurveyID)
		if err != nil {
			return nil, err
		}
		survey.DpChannel <- 1
	}

	if recq.IntraMessage == false {
		survey, err := s.getSurvey(recq.SurveyID)
		if err != nil {
			return nil, err
		}

		counter := len(recq.Roster.List) - 1
		for counter > 0 {
			counter = counter - (<-survey.SurveyChannel)
		}
	}
	return &ServiceState{recq.SurveyID}, nil
}

// HandleSurveyResponseQuery handles a survey answers submission by a subject.
func (s *Service) HandleSurveyResponseQuery(resp *SurveyResponseQuery) (network.Message, error) {
	survey, err := s.getSurvey(resp.SurveyID)
	if err != nil {
		return nil, err
	}
	if err = s.PushData(resp, survey.Query.Proofs); err != nil {
		return nil, err
	}

	//number of data providers who have already pushed the data
	survey.DpChannel <- 1
	return &ServiceState{"1"}, nil
}

// HandleSurveyResultsQuery handles the survey result query by the surveyor.
func (s *Service) HandleSurveyResultsQuery(resq *SurveyResultsQuery) (network.Message, error) {
	log.Lvl1(s.ServerIdentity(), " received a survey result query")

	survey, err := s.getSurvey(resq.SurveyID)
	if err != nil {
		return nil, err
	}

	survey.Query.ClientPubKey = resq.ClientPublic
	err = s.putSurvey(resq.SurveyID, survey)
	if err != nil {
		return nil, err
	}

	if resq.IntraMessage == false {
		resq.IntraMessage = true

		err := libunlynxtools.SendISMOthers(s.ServiceProcessor, &survey.Query.Roster, resq)
		if err != nil {
			return nil, err
		}
		err = s.StartService(resq.SurveyID, true)
		if err != nil {
			return nil, err
		}

		log.Lvl1(s.ServerIdentity(), " completed the query processing...")

		survey, err := s.getSurvey(resq.SurveyID)
		if err != nil {
			return nil, err
		}
		results := survey.PullDeliverableResults(false, libunlynx.CipherText{})
		err = s.putSurvey(resq.SurveyID, survey)
		if err != nil {
			return nil, err
		}

		return &ServiceResult{Results: results}, nil
	}

	return nil, s.StartService(resq.SurveyID, false)
}

// HandleDDTfinished handles the message DDTfinished: one of the nodes is ready to perform a collective aggregation
func (s *Service) HandleDDTfinished(recq *DDTfinished) (network.Message, error) {
	survey, err := s.getSurvey(recq.SurveyID)
	if err != nil {
		return nil, err
	}
	survey.DDTChannel <- 1
	return nil, nil
}

// HandleQueryBroadcastFinished handles the message QueryBroadcastFinished: one of the nodes has already received the query
func (s *Service) HandleQueryBroadcastFinished(recq *QueryBroadcastFinished) (network.Message, error) {
	survey, err := s.getSurvey(recq.SurveyID)
	if err != nil {
		return nil, err
	}
	survey.SurveyChannel <- 1
	return nil, nil
}

// Protocol Handlers
//______________________________________________________________________________________________________________________

// NewProtocol creates a protocol instance executed by all nodes
func (s *Service) NewProtocol(tn *onet.TreeNodeInstance, conf *onet.GenericConfig) (onet.ProtocolInstance, error) {
	tn.SetConfig(conf)

	var pi onet.ProtocolInstance
	target := SurveyID(string(conf.Data))
	survey, err := s.getSurvey(SurveyID(conf.Data))
	if err != nil {
		return nil, err
	}

	switch tn.ProtocolName() {
	case protocolsunlynx.ShufflingProtocolName:
		pi, err = protocolsunlynx.NewShufflingProtocol(tn)
		if err != nil {
			return nil, err
		}
		shuffle := pi.(*protocolsunlynx.ShufflingProtocol)

		shuffle.Proofs = survey.Query.Proofs
		shuffle.ProofFunc = func(shuffleTarget, shuffledData []libunlynx.CipherVector, collectiveKey kyber.Point, beta [][]kyber.Scalar, pi []int) *libunlynxshuffle.PublishedShufflingProof {
			proof, err := libunlynxshuffle.ShuffleProofCreation(shuffleTarget, shuffledData, libunlynx.SuiTe.Point().Base(), collectiveKey, beta, pi)
			if err != nil {
				log.Fatal(err)
			}
			return &proof
		}
		shuffle.Precomputed = survey.ShufflePrecompute
		if tn.IsRoot() {
			dpResponses := survey.PullDpResponses()
			var toShuffleCV []libunlynx.CipherVector
			toShuffleCV, survey.Lengths = protocolsunlynx.ProcessResponseToMatrixCipherText(dpResponses)
			shuffle.ShuffleTarget = &toShuffleCV

			err = s.putSurvey(target, survey)
			if err != nil {
				return nil, err
			}
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
				cv := libunlynx.CipherVector{v.Value}
				queryWhereToTag = append(queryWhereToTag, libunlynx.ProcessResponse{WhereEnc: cv, GroupByEnc: nil, AggregatingAttributes: nil})
			}
			shuffledClientResponses = append(queryWhereToTag, shuffledClientResponses...)
			deterministicTOS := protocolsunlynx.ProcessResponseToCipherVector(shuffledClientResponses)
			survey.TargetOfSwitch = shuffledClientResponses
			err = s.putSurvey(target, survey)
			if err != nil {
				return nil, err
			}

			hashCreation.TargetOfSwitch = &deterministicTOS
		}

	case protocolsunlynx.CollectiveAggregationProtocolName:
		pi, err = protocolsunlynx.NewCollectiveAggregationProtocol(tn)
		if err != nil {
			return nil, err
		}

		// waits for all other nodes to finish the tagging phase
		groupedData := survey.PullLocallyAggregatedResponses()
		err = s.putSurvey(target, survey)
		if err != nil {
			return nil, err
		}

		collectiveAggr := pi.(*protocolsunlynx.CollectiveAggregationProtocol)
		collectiveAggr.GroupedData = &groupedData
		collectiveAggr.Proofs = survey.Query.Proofs
		collectiveAggr.ProofFunc = func(data []libunlynx.CipherVector, res libunlynx.CipherVector) *libunlynxaggr.PublishedAggregationListProof {
			proof := libunlynxaggr.AggregationListProofCreation(data, res)
			return &proof
		}

		counter := len(tn.Roster().List) - 1
		for counter > 0 {
			counter = counter - (<-survey.DDTChannel)
		}

	case protocolsunlynx.DROProtocolName:
		pi, err := protocolsunlynx.NewShufflingProtocol(tn)
		if err != nil {
			return nil, err
		}

		shuffle := pi.(*protocolsunlynx.ShufflingProtocol)
		shuffle.Proofs = survey.Query.Proofs
		shuffle.ProofFunc = func(shuffleTarget, shuffledData []libunlynx.CipherVector, collectiveKey kyber.Point, beta [][]kyber.Scalar, pi []int) *libunlynxshuffle.PublishedShufflingProof {
			proof, err := libunlynxshuffle.ShuffleProofCreation(shuffleTarget, shuffledData, libunlynx.SuiTe.Point().Base(), collectiveKey, beta, pi)
			if err != nil {
				log.Fatal(err)
			}
			return &proof
		}
		shuffle.Precomputed = nil

		if tn.IsRoot() {
			clientResponses := make([]libunlynx.ProcessResponse, 0)
			noiseArray := libunlynxdiffprivacy.GenerateNoiseValues(1000, 0, 1, 0.1, 0)
			for _, v := range noiseArray {
				clientResponses = append(clientResponses, libunlynx.ProcessResponse{GroupByEnc: nil, AggregatingAttributes: libunlynx.IntArrayToCipherVector([]int64{int64(v)})})
			}
			var toShuffleCV []libunlynx.CipherVector
			toShuffleCV, survey.Lengths = protocolsunlynx.ProcessResponseToMatrixCipherText(clientResponses)
			shuffle.ShuffleTarget = &toShuffleCV
		}
		return pi, nil

	case protocolsunlynx.KeySwitchingProtocolName:
		pi, err = protocolsunlynx.NewKeySwitchingProtocol(tn)
		if err != nil {
			return nil, err
		}

		keySwitch := pi.(*protocolsunlynx.KeySwitchingProtocol)
		keySwitch.Proofs = survey.Query.Proofs
		keySwitch.ProofFunc = func(pubKey, targetPubKey kyber.Point, secretKey kyber.Scalar, ks2s, rBNegs []kyber.Point, vis []kyber.Scalar) *libunlynxkeyswitch.PublishedKSListProof {
			proof, err := libunlynxkeyswitch.KeySwitchListProofCreation(pubKey, targetPubKey, secretKey, ks2s, rBNegs, vis)
			if err != nil {
				log.Fatal(err)
			}
			return &proof
		}

		if tn.IsRoot() {
			var coaggr []libunlynx.FilteredResponse

			if libunlynx.DIFFPRI == true {
				coaggr = survey.PullCothorityAggregatedFilteredResponses(true, survey.Noise)
			} else {
				coaggr = survey.PullCothorityAggregatedFilteredResponses(false, libunlynx.CipherText{})
			}
			var cv libunlynx.CipherVector
			cv, survey.Lengths = protocolsunlynx.FilteredResponseToCipherVector(coaggr)
			keySwitch.TargetOfSwitch = &cv
			cpk := survey.Query.ClientPubKey
			keySwitch.TargetPublicKey = &cpk

			err = s.putSurvey(target, survey)
			if err != nil {
				return nil, err
			}
		}
	default:
		return nil, fmt.Errorf("service attempts to start an unknown protocol: " + tn.ProtocolName())
	}
	return pi, nil
}

// StartProtocol starts a specific protocol (Pipeline, Shuffling, etc.)
func (s *Service) StartProtocol(name string, targetSurvey SurveyID) (onet.ProtocolInstance, error) {
	survey, err := s.getSurvey(targetSurvey)
	if err != nil {
		return nil, err
	}
	tree := survey.Query.Roster.GenerateNaryTreeWithRoot(2, s.ServerIdentity())

	var tn *onet.TreeNodeInstance
	tn = s.NewTreeNodeInstance(tree, tree.Root, name)

	conf := onet.GenericConfig{Data: []byte(string(targetSurvey))}

	pi, err := s.NewProtocol(tn, &conf)
	if err != nil {
		return nil, fmt.Errorf("error running "+name+" : %v", err)
	}

	err = s.RegisterProtocolInstance(pi)
	if err != nil {
		return nil, err
	}

	go func(pname string) {
		if tmpErr := pi.Dispatch(); tmpErr != nil {
			log.Error("Error running Dispatch ->" + name + " :" + err.Error())
		}
	}(name)
	go func(pname string) {
		if tmpErr := pi.Start(); tmpErr != nil {
			log.Error("Error running Start ->" + name + " :" + err.Error())
		}
	}(name)

	return pi, err
}

// Service Phases
//______________________________________________________________________________________________________________________

// StartService starts the service (with all its different steps/protocols)
func (s *Service) StartService(targetSurvey SurveyID, root bool) error {
	log.Lvl1(s.ServerIdentity(), " is waiting on channel")

	survey, err := s.getSurvey(targetSurvey)
	if err != nil {
		return err
	}

	counter := survey.Query.MapDPs[s.ServerIdentity().String()]
	for counter > int64(0) {
		log.Lvl1(s.ServerIdentity(), " is waiting for ", counter, " data providers to send their data")
		counter = counter - int64(<-survey.DpChannel)
	}
	log.Lvl1("All data providers (", survey.Query.MapDPs[s.ServerIdentity().String()], ") for server ", s.ServerIdentity(), " have sent their data")

	log.Lvl1(s.ServerIdentity(), " starts a UnLynx Protocol for survey ", targetSurvey)

	target, err := s.getSurvey(targetSurvey)
	if err != nil {
		return err
	}

	// Shuffling Phase
	start := libunlynx.StartTimer(s.ServerIdentity().String() + "_ShufflingPhase")

	err = s.ShufflingPhase(survey.Query.SurveyID)
	if err != nil {
		return fmt.Errorf("error in the Shuffling Phase: %v", err)
	}

	libunlynx.EndTimer(start)
	// Tagging Phase
	start = libunlynx.StartTimer(s.ServerIdentity().String() + "_TaggingPhase")

	err = s.TaggingPhase(target.Query.SurveyID)
	if err != nil {
		return fmt.Errorf("error in the Tagging Phase: %v", err)
	}

	// broadcasts the query to unlock waiting channel
	aux := target.Query.Roster
	err = libunlynxtools.SendISMOthers(s.ServiceProcessor, &aux, &DDTfinished{SurveyID: targetSurvey})
	if err != nil {
		return err
	}

	libunlynx.EndTimer(start)

	// Aggregation Phase
	if root == true {
		start := libunlynx.StartTimer(s.ServerIdentity().String() + "_AggregationPhase")

		err = s.AggregationPhase(target.Query.SurveyID)
		if err != nil {
			return fmt.Errorf("error in the Aggregation Phase: %v", err)
		}

		libunlynx.EndTimer(start)
	}

	// DRO Phase
	if root == true && libunlynx.DIFFPRI == true {
		start := libunlynx.StartTimer(s.ServerIdentity().String() + "_DROPhase")

		err := s.DROPhase(target.Query.SurveyID)
		if err != nil {
			return fmt.Errorf("error in the DRO Phase: %v", err)
		}

		libunlynx.EndTimer(start)
	}

	// Key Switch Phase
	if root == true {
		start := libunlynx.StartTimer(s.ServerIdentity().String() + "_KeySwitchingPhase")

		err := s.KeySwitchingPhase(target.Query.SurveyID)
		if err != nil {
			return fmt.Errorf("error in the Key Switching Phase: %v", err)
		}

		libunlynx.EndTimer(start)
	}

	return nil
}

// ShufflingPhase performs the shuffling of the ClientResponses
func (s *Service) ShufflingPhase(targetSurvey SurveyID) error {
	survey, err := s.getSurvey(targetSurvey)
	if err != nil {
		return err
	}

	if len(survey.DpResponses) == 0 && len(survey.DpResponsesAggr) == 0 {
		log.Lvl1(s.ServerIdentity(), " no data to shuffle")
		return nil
	}

	pi, err := s.StartProtocol(protocolsunlynx.ShufflingProtocolName, targetSurvey)
	if err != nil {
		return err
	}

	var tmpShufflingResult []libunlynx.CipherVector
	select {
	case tmpShufflingResult = <-pi.(*protocolsunlynx.ShufflingProtocol).FeedbackChannel:
	case <-time.After(libunlynx.TIMEOUT):
		return fmt.Errorf(s.ServerIdentity().String() + " didn't get the <tmpShufflingResult> on time")
	}

	survey, err = s.getSurvey(targetSurvey)
	if err != nil {
		return err
	}
	shufflingResult := protocolsunlynx.MatrixCipherTextToProcessResponse(tmpShufflingResult, survey.Lengths)

	survey.PushShuffledProcessResponses(shufflingResult)
	err = s.putSurvey(targetSurvey, survey)
	return err
}

// TaggingPhase performs the private grouping on the currently collected data.
func (s *Service) TaggingPhase(targetSurvey SurveyID) error {
	survey, err := s.getSurvey(targetSurvey)
	if err != nil {
		return err
	}

	if len(survey.ShuffledProcessResponses) == 0 {
		log.Lvl1(s.ServerIdentity(), "  for survey ", survey.Query.SurveyID, " has no data to det tag")
		return nil
	}

	pi, err := s.StartProtocol(protocolsunlynx.DeterministicTaggingProtocolName, targetSurvey)
	if err != nil {
		return err
	}

	var tmpDeterministicTaggingResult []libunlynx.DeterministCipherText
	select {
	case tmpDeterministicTaggingResult = <-pi.(*protocolsunlynx.DeterministicTaggingProtocol).FeedbackChannel:
	case <-time.After(libunlynx.TIMEOUT):
		return fmt.Errorf(s.ServerIdentity().String() + " didn't get the <tmpDeterministicTaggingResult> on time")
	}

	survey, err = s.getSurvey(targetSurvey)
	if err != nil {
		return err
	}
	deterministicTaggingResult := protocolsunlynx.DeterCipherVectorToProcessResponseDet(tmpDeterministicTaggingResult, survey.TargetOfSwitch)

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
	err = s.putSurvey(targetSurvey, survey)
	return err
}

// AggregationPhase performs the per-group aggregation on the currently grouped data.
func (s *Service) AggregationPhase(targetSurvey SurveyID) error {
	pi, err := s.StartProtocol(protocolsunlynx.CollectiveAggregationProtocolName, targetSurvey)
	if err != nil {
		return err
	}

	var tmpAggreagtionResult protocolsunlynx.CothorityAggregatedData
	select {
	case tmpAggreagtionResult = <-pi.(*protocolsunlynx.CollectiveAggregationProtocol).FeedbackChannel:
	case <-time.After(libunlynx.TIMEOUT):
		return fmt.Errorf(s.ServerIdentity().String() + " didn't get the <tmpAggreagtionResult> on time")
	}

	survey, err := s.getSurvey(targetSurvey)
	if err != nil {
		return err
	}

	survey.PushCothorityAggregatedFilteredResponses(tmpAggreagtionResult.GroupedData)
	err = s.putSurvey(targetSurvey, survey)
	return err
}

// DROPhase shuffles the list of noise values.
func (s *Service) DROPhase(targetSurvey SurveyID) error {
	pi, err := s.StartProtocol(protocolsunlynx.DROProtocolName, targetSurvey)
	if err != nil {
		return err
	}

	survey, err := s.getSurvey(targetSurvey)
	if err != nil {
		return err
	}

	var tmpShufflingResult []libunlynx.CipherVector
	select {
	case tmpShufflingResult = <-pi.(*protocolsunlynx.ShufflingProtocol).FeedbackChannel:
	case <-time.After(libunlynx.TIMEOUT):
		return fmt.Errorf(s.ServerIdentity().String() + " didn't get the <tmpShufflingResult> on time")
	}

	shufflingResult := protocolsunlynx.MatrixCipherTextToProcessResponse(tmpShufflingResult, survey.Lengths)

	survey.Noise = shufflingResult[0].AggregatingAttributes[0]
	err = s.putSurvey(targetSurvey, survey)
	return err
}

// KeySwitchingPhase performs the switch to the querier's key on the currently aggregated data.
func (s *Service) KeySwitchingPhase(targetSurvey SurveyID) error {
	pi, err := s.StartProtocol(protocolsunlynx.KeySwitchingProtocolName, targetSurvey)
	if err != nil {
		return err
	}

	survey, err := s.getSurvey(targetSurvey)
	if err != nil {
		return err
	}

	var tmpKeySwitchingResult libunlynx.CipherVector
	select {
	case tmpKeySwitchingResult = <-pi.(*protocolsunlynx.KeySwitchingProtocol).FeedbackChannel:
	case <-time.After(libunlynx.TIMEOUT):
		return fmt.Errorf(s.ServerIdentity().String() + " didn't get the <tmpKeySwitchingResult> on time")
	}

	keySwitchedAggregatedResponses := protocolsunlynx.CipherVectorToFilteredResponse(tmpKeySwitchingResult, survey.Lengths)

	survey.PushQuerierKeyEncryptedResponses(keySwitchedAggregatedResponses)
	err = s.putSurvey(targetSurvey, survey)
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
