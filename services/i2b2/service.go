package serviceI2B2

import (
	"bufio"
	"fmt"
	"github.com/btcsuite/goleveldb/leveldb/errors"
	"github.com/fanliao/go-concurrentMap"
	"github.com/lca1/unlynx/lib"
	"github.com/lca1/unlynx/protocols"
	"github.com/lca1/unlynx/services"
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/crypto.v0/base64"
	"gopkg.in/dedis/crypto.v0/random"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/dedis/onet.v1/network"
	"os"
	"strings"
	"sync"
	"time"
)

// ServiceName is the registered name for the unlynx service.
const ServiceName = "UnLynxI2b2"

// DDTSecretsPath filename
const DDTSecretsPath = "ddt_secrets_"

// TimeResults includes all variables that will store the durations (to collect the execution/communication time)
type TimeResults struct {
	DDTparsingTime       time.Duration // Total parsing time (i2b2 -> unlynx client)
	DDTRequestTimeExec   time.Duration // Total DDT (of the request) execution time
	DDTRequestTimeCommun time.Duration // Total DDT (of the request) communication time

	AggParsingTime       time.Duration // Total parsing time (i2b2 -> unlynx client)
	AggRequestTimeExec   time.Duration // Total Agg (of the request) execution time
	AggRequestTimeCommun time.Duration // Total Agg (of the request) communication time
	LocalAggregationTime time.Duration // Total local aggregation time
}

// SurveyID unique ID for each survey.
type SurveyID string

// SurveyDDTRequestTerms is the message used trigger the DDT of the query parameters
type SurveyDDTRequest struct {
	SurveyID SurveyID
	Roster   onet.Roster
	Proofs   bool

	Terms lib.CipherVector // query terms

	// message handling
	IntraMessage  bool
	MessageSource *network.ServerIdentity
}

// SurveyAggRequest is the message used trigger the aggregation of the final results (well it's mostly shuffling and key switching)
type SurveyAggRequest struct {
	SurveyID SurveyID
	Roster   onet.Roster
	Proofs   bool
	ClientPubKey abstract.Point // we need this for the key switching

	Aggregate []lib.CipherText 			// aggregated final result. It is an array because we the root node adds the results from the other nodes here
	AggregateShuffled []lib.ProcessResponse       	// aggregated final results after they are shuffled

	// message handling
	IntraMessage  bool
	MessageSource *network.ServerIdentity
}

// SurveyTag is the struct that we persist in the service that contains all the data for the DDT protocol
type SurveyTag struct {
	SurveyID      SurveyID
	Request       SurveyDDTRequest
	SurveyChannel chan int // To wait for the survey to be created before the DDT protocol
}

// SurveyAgg is the struct that we persist in the service that contains all the data for the Aggregation request phase
type SurveyAgg struct {
	SurveyID      SurveyID
	Request       SurveyAggRequest
	SurveyChannel chan int // To wait for all the aggregate results to be received by the root node
}

// SurveyGenerated is used to ensure that all servers get the survey before starting the DDT protocol
type SurveyGenerated struct {
	SurveyID SurveyID
}

func castToSurveyTag(object interface{}, err error) SurveyTag {
	if err != nil {
		log.Error("Error reading SurveyTag map")
	}
	return object.(SurveyTag)
}

func castToSurveyAgg(object interface{}, err error) SurveyAgg {
	if err != nil {
		log.Error("Error reading SurveyAgg map")
	}
	return object.(SurveyAgg)
}

// MsgTypes defines the Message Type ID for all the service's intra-messages.
type MsgTypes struct {
	msgSurveyDDTRequestTerms network.MessageTypeID
	msgSurveyGenerated       network.MessageTypeID
	msgSurveyAggRequest      network.MessageTypeID
}

var msgTypes = MsgTypes{}

func init() {
	onet.RegisterNewService(ServiceName, NewService)

	// messages for DDT Request
	msgTypes.msgSurveyDDTRequestTerms = network.RegisterMessage(&SurveyDDTRequest{})
	msgTypes.msgSurveyGenerated = network.RegisterMessage(&SurveyGenerated{})
	network.RegisterMessage(&ServiceResultDDT{})

	// messages for Agg Request
	msgTypes.msgSurveyAggRequest = network.RegisterMessage(&SurveyAggRequest{})
	network.RegisterMessage(&ServiceResultAgg{})
}

// ServiceResultDDT will contain final results of the DDT of the query terms.
type ServiceResultDDT struct {
	Result []lib.GroupingKey
	TR     TimeResults // contains all the time measurements
}

// ServiceResultAgg will contain final aggregate result to sent to the client.
type ServiceResultAgg struct {
	Result lib.CipherText
	TR     TimeResults // contains all the time measurements
}

// Service defines a service in unlynx
type Service struct {
	*onet.ServiceProcessor

	MapSurveyTag *concurrent.ConcurrentMap
	MapSurveyAgg *concurrent.ConcurrentMap
	Mutex        *sync.Mutex
	Proofs       bool
	TR           TimeResults // contains all the time measurements
}

// NewService constructor which registers the needed messages.
func NewService(c *onet.Context) onet.Service {

	newUnLynxInstance := &Service{
		ServiceProcessor: onet.NewServiceProcessor(c),
		MapSurveyTag:     concurrent.NewConcurrentMap(),
		MapSurveyAgg:     concurrent.NewConcurrentMap(),
		Mutex:            &sync.Mutex{},
	}

	if cerr := newUnLynxInstance.RegisterHandler(newUnLynxInstance.HandleSurveyDDTRequestTerms); cerr != nil {
		log.Error("Wrong Handler.", cerr)
	}
	if cerr := newUnLynxInstance.RegisterHandler(newUnLynxInstance.HandleSurveyAggRequest); cerr != nil {
		log.Error("Wrong Handler.", cerr)
	}

	c.RegisterProcessor(newUnLynxInstance, msgTypes.msgSurveyDDTRequestTerms)
	c.RegisterProcessor(newUnLynxInstance, msgTypes.msgSurveyGenerated)

	c.RegisterProcessor(newUnLynxInstance, msgTypes.msgSurveyAggRequest)

	return newUnLynxInstance
}

// Process implements the processor interface and is used to recognize messages broadcasted between servers
func (s *Service) Process(msg *network.Envelope) {
	if msg.MsgType.Equal(msgTypes.msgSurveyDDTRequestTerms) {
		tmp := (msg.Msg).(*SurveyDDTRequest)
		s.HandleSurveyDDTRequestTerms(tmp)
	} else if msg.MsgType.Equal(msgTypes.msgSurveyGenerated) {
		tmp := (msg.Msg).(*SurveyGenerated)
		s.HandleSurveyGenerated(tmp)
	} else if msg.MsgType.Equal(msgTypes.msgSurveyAggRequest) {
		tmp := (msg.Msg).(*SurveyAggRequest)
		s.HandleSurveyAggRequest(tmp)
	} else {
		log.Fatal("Cannot identify the intra-message")
	}
}

// Request Handlers
//______________________________________________________________________________________________________________________

// HandleSurveyGenerated handles triggers the SurveyDDTChannel
func (s *Service) HandleSurveyGenerated(recq *SurveyGenerated) (network.Message, onet.ClientError) {
	(castToSurveyTag(s.MapSurveyTag.Get((string)(recq.SurveyID))).SurveyChannel) <- 1
	return nil, nil
}

// HandleSurveyDDTRequestTerms handles the reception of the query terms to be deterministically tagged
func (s *Service) HandleSurveyDDTRequestTerms(sdq *SurveyDDTRequest) (network.Message, onet.ClientError) {

	// if this server is the one receiving the request from the client
	if !sdq.IntraMessage {
		log.Lvl1(s.ServerIdentity().String(), " received a SurveyDDTRequestTerms:", sdq.SurveyID)

		if len(sdq.Terms) == 0 {
			log.Lvl1(s.ServerIdentity(), " for survey", sdq.SurveyID, "has no data to det tag")
			return &ServiceResultDDT{}, nil
		}

		// initialize timers
		s.TR = TimeResults{DDTRequestTimeExec: 0, DDTRequestTimeCommun: 0}


		s.MapSurveyTag.Put((string)(sdq.SurveyID),
			SurveyTag{
				SurveyID:      sdq.SurveyID,
				Request:       *sdq,
				SurveyChannel: make(chan int, 100),
			})

		// signal the other nodes that they need to prepare to execute a DDT (no need to send the terms)
		err := services.SendISMOthers(s.ServiceProcessor, &sdq.Roster,
			&SurveyDDTRequest{
				SurveyID:      sdq.SurveyID,
				Roster:        sdq.Roster,
				IntraMessage:  true,
				MessageSource: s.ServerIdentity(),
				Proofs:        sdq.Proofs,
			})

		if err != nil {
			log.Error("broadcasting error ", err)
		}

		// waits for all other nodes to receive the survey
		counter := len(sdq.Roster.List) - 1
		for counter > 0 {
			counter = counter - <-castToSurveyTag(s.MapSurveyTag.Get((string)(sdq.SurveyID))).SurveyChannel
		}

		deterministicTaggingResult, err := s.TaggingPhase(sdq.SurveyID, &sdq.Roster)

		if err != nil {
			log.Error("DDT error", err)
			return nil, onet.NewClientError(err)
		}

		start := time.Now()

		// convert the result to of the tagging for something close to the XML response of i2b2 (array of tagged terms)
		listTaggedTerms := make([]lib.GroupingKey, 0)

		for _, el := range deterministicTaggingResult {
			listTaggedTerms = append(listTaggedTerms, el.DetTagWhere[0])
		}

		s.MapSurveyTag.Remove((string)(sdq.SurveyID))

		s.TR.DDTRequestTimeExec += time.Since(start)

		return &ServiceResultDDT{Result: listTaggedTerms, TR: s.TR}, nil
	}

	log.Lvl1(s.ServerIdentity().String(), " is notified of survey:", sdq.SurveyID)

	s.MapSurveyTag.Put((string)(sdq.SurveyID),
		SurveyTag{
			SurveyID: sdq.SurveyID,
			Request:  *sdq,
		})

	// sends a signal to unlock waiting channel
	err := s.SendRaw(sdq.MessageSource, &SurveyGenerated{SurveyID: sdq.SurveyID})
	if err != nil {
		log.Error("sending error ", err)
	}

	return nil, nil
}

// HandleSurveyAggRequest handles the reception of the aggregate local result to be shared/shuffled/switched
func (s *Service) HandleSurveyAggRequest(sar *SurveyAggRequest) (network.Message, onet.ClientError) {
	s.Proofs = sar.Proofs
	log.Lvl1(s.ServerIdentity().String(), " received a SurveyAggRequest:", sar.SurveyID)

	var root bool
	if s.ServerIdentity().String() == sar.Roster.List[0].String() {
		root = true
	} else {
		root = false
	}

	// if this server is the one receiving the request from the client and it is the root node for this phase
	if !sar.IntraMessage && root {
		// initialize timers
		s.TR = TimeResults{AggRequestTimeExec: 0, AggRequestTimeCommun: 0}

		s.MapSurveyAgg.Put((string)(sar.SurveyID),
			SurveyAgg{
				SurveyID:      sar.SurveyID,
				Request:       *sar,
				SurveyChannel: make(chan int, 100),
			})


		// wait until you've got all the aggregate results from the other nodes
		counter := len(sar.Roster.List) - 1
		for counter > 0 {
			counter = counter - <-castToSurveyAgg(s.MapSurveyAgg.Get((string)(sar.SurveyID))).SurveyChannel
		}

		survey := castToSurveyAgg(s.MapSurveyAgg.Get((string)(sar.SurveyID)))
		if len(survey.Request.Aggregate) == 0 {
			log.Lvl1(s.ServerIdentity(), " no data to shuffle")
		} else {
			// shuffle the results
			shufflingResult, err := s.ShufflingPhase(sar.SurveyID, &sar.Roster)

			if err != nil {
				log.Error("shuffling error", err)
				return nil, onet.NewClientError(err)
			}

			survey.Request.AggregateShuffled = shufflingResult
			s.MapSurveyAgg.Put((string)(sar.SurveyID),survey)

			// send the shuffled results to all the other nodes
			sar.AggregateShuffled = shufflingResult
			sar.IntraMessage = true
			sar.MessageSource = s.ServerIdentity()

			// let's delete what we don't need (less communication time)
			sar.Aggregate = nil

			// signal the other nodes that they need to prepare to execute a key switching
			err = services.SendISMOthers(s.ServiceProcessor, &sar.Roster, sar)
			if err != nil {
				log.Error("broadcasting error ", err)
			}

			// key switch the results
			keySwitchingResult, err := s.KeySwitchingPhase(sar.SurveyID, &sar.Roster)

			if err != nil {
				log.Error("key switching error", err)
				return nil, onet.NewClientError(err)
			}

			// get server index
			index := 0
			for i, r := range sar.Roster.List {
				if r.String() == s.ServerIdentity().String(){
					index = i
					break
				}
			}

			return &ServiceResultAgg{Result: keySwitchingResult[index].AggregatingAttributes[0], TR: s.TR}, nil
		}
	} else if !sar.IntraMessage && !root { // if message sent by client and not root
		// initialize timers
		s.TR = TimeResults{AggRequestTimeExec: 0, AggRequestTimeCommun: 0}

		s.MapSurveyAgg.Put((string)(sar.SurveyID),
			SurveyAgg{
				SurveyID:      sar.SurveyID,
				Request:       *sar,
			})

		sar.IntraMessage = true
		sar.MessageSource = s.ServerIdentity()

		// send your local aggregate result to the root server (index 0)
		err := s.SendRaw(sar.Roster.List[0], sar)
		if err != nil {
			log.Error(s.ServerIdentity().String() + "could not send its aggregate value", err)
		}
	} else if sar.IntraMessage && root {
		s.Mutex.Lock()
		survey := castToSurveyAgg(s.MapSurveyAgg.Get((string)(sar.SurveyID)))
		survey.Request.Aggregate = append(survey.Request.Aggregate, sar.Aggregate...)
		s.MapSurveyAgg.Put((string)(sar.SurveyID),survey)
		s.Mutex.Unlock()

		// get the request from the other non-root nodes
		(castToSurveyTag(s.MapSurveyAgg.Get((string)(sar.SurveyID))).SurveyChannel) <- 1

	} else { // basically after shuffling the results the root server needs to send them back
		// to the remaining nodes for key switching

		// update the local survey with the shuffled results
		s.Mutex.Lock()
		survey := castToSurveyAgg(s.MapSurveyAgg.Get((string)(sar.SurveyID)))
		survey.Request.AggregateShuffled = sar.AggregateShuffled
		s.MapSurveyAgg.Put((string)(sar.SurveyID),survey)
		s.Mutex.Unlock()

		// key switch the results
		keySwitchingResult, err := s.KeySwitchingPhase(sar.SurveyID, &sar.Roster)

		if err != nil {
			log.Error("key switching error", err)
			return nil, onet.NewClientError(err)
		}

		// get server index
		index := 0
		for i, r := range sar.Roster.List {
			if r.String() == s.ServerIdentity().String(){
				index = i
				break
			}
		}

		return &ServiceResultAgg{Result: keySwitchingResult[index].AggregatingAttributes[0], TR: s.TR}, nil
	}

	return nil, nil
}


// Protocol Handlers
//______________________________________________________________________________________________________________________

// NewProtocol creates a protocol instance executed by all nodes
func (s *Service) NewProtocol(tn *onet.TreeNodeInstance, conf *onet.GenericConfig) (onet.ProtocolInstance, error) {
	tn.SetConfig(conf)

	var pi onet.ProtocolInstance
	var err error

	switch tn.ProtocolName() {
	case protocols.DeterministicTaggingProtocolName:
		target := SurveyID(string(conf.Data))
		survey := castToSurveyTag(s.MapSurveyTag.Get(string(target)))

		pi, err = protocols.NewDeterministicTaggingProtocol(tn)
		if err != nil {
			return nil, err
		}
		hashCreation := pi.(*protocols.DeterministicTaggingProtocol)

		var serverIDMap *network.ServerIdentity

		if tn.IsRoot() {
			dataToDDT := make([]lib.ProcessResponse, 0)

			for _, el := range survey.Request.Terms {
				term := make(lib.CipherVector, 0)
				term = append(term, el)
				dataToDDT = append(dataToDDT, lib.ProcessResponse{WhereEnc: term})
			}

			hashCreation.TargetOfSwitch = &dataToDDT

			serverIDMap = s.ServerIdentity()
		} else {
			serverIDMap = survey.Request.MessageSource
		}

		s.Mutex.Lock()

		aux, err := checkDDTSecrets(DDTSecretsPath+s.ServerIdentity().Address.Host()+":"+s.ServerIdentity().Address.Port()+".txt", serverIDMap.Address)
		if err != nil || aux == nil {
			log.Fatal("Error while reading the DDT secrets from file", err)
		}

		s.Mutex.Unlock()

		hashCreation.SurveySecretKey = &aux
		hashCreation.Proofs = survey.Request.Proofs //for now we have no proofs in the i2b2 version of UnLynx
	case protocols.ShufflingProtocolName:
		pi, err := protocols.NewShufflingProtocol(tn)
		if err != nil {
			return nil, err
		}

		shuffle := pi.(*protocols.ShufflingProtocol)
		shuffle.Proofs = s.Proofs
		shuffle.Precomputed = nil

		if tn.IsRoot() {
			target := SurveyID(string(conf.Data))
			survey := castToSurveyAgg(s.MapSurveyAgg.Get(string(target)))

			dataToShuffle := make([]lib.ProcessResponse,0)

			for _, el := range survey.Request.Aggregate {
				aggregate := make(lib.CipherVector, 0)
				aggregate = append(aggregate, el)
				dataToShuffle = append(dataToShuffle, lib.ProcessResponse{WhereEnc: aggregate})
			}

			shuffle.TargetOfShuffle = &dataToShuffle
		}
		return pi, nil
	case protocols.KeySwitchingProtocolName:
		pi, err = protocols.NewKeySwitchingProtocol(tn)
		if err != nil {
			return nil, err
		}

		keySwitch := pi.(*protocols.KeySwitchingProtocol)
		keySwitch.Proofs = s.Proofs

		if tn.IsRoot() {
			target := SurveyID(string(conf.Data))
			survey := castToSurveyAgg(s.MapSurveyAgg.Get(string(target)))

			dataToSwitch := []lib.FilteredResponse{}

			for _, el := range survey.Request.AggregateShuffled {
				dataToSwitch = append(dataToSwitch, lib.FilteredResponse{AggregatingAttributes: el.WhereEnc})
			}

			keySwitch.TargetOfSwitch = &dataToSwitch
			tmp := survey.Request.ClientPubKey
			keySwitch.TargetPublicKey = &tmp
		}
	default:
		return nil, errors.New("Service attempts to start an unknown protocol: " + tn.ProtocolName() + ".")
	}

	return pi, nil
}

// StartProtocol starts a specific protocol (Pipeline, Shuffling, etc.)
func (s *Service) StartProtocol(name string, targetSurvey SurveyID, roster *onet.Roster) (onet.ProtocolInstance, error) {
	tree := roster.GenerateNaryTreeWithRoot(2, s.ServerIdentity())
	tn := s.NewTreeNodeInstance(tree, tree.Root, name)

	conf := onet.GenericConfig{Data: []byte(string(targetSurvey))}

	pi, err := s.NewProtocol(tn, &conf)

	s.RegisterProtocolInstance(pi)

	go pi.Dispatch()
	go pi.Start()

	return pi, err
}

// Service Phases
//______________________________________________________________________________________________________________________

// TaggingPhase performs the private grouping on the currently collected data.
func (s *Service) TaggingPhase(targetSurvey SurveyID, roster *onet.Roster) ([]lib.ProcessResponseDet, error) {
	start := time.Now()
	pi, err := s.StartProtocol(protocols.DeterministicTaggingProtocolName, targetSurvey, roster)
	if err != nil {
		return nil, err
	}
	s.TR.DDTRequestTimeExec += time.Since(start)

	deterministicTaggingResult := <-pi.(*protocols.DeterministicTaggingProtocol).FeedbackChannel

	s.TR.DDTRequestTimeExec += pi.(*protocols.DeterministicTaggingProtocol).ExecTime
	s.TR.DDTRequestTimeCommun = time.Since(start) - s.TR.DDTRequestTimeExec

	return deterministicTaggingResult, nil
}

// ShufflingPhase performs the shuffling aggregated results from each of the nodes
func (s *Service) ShufflingPhase(targetSurvey SurveyID, roster *onet.Roster) ([]lib.ProcessResponse, error) {
	start := time.Now()
	pi, err := s.StartProtocol(protocols.ShufflingProtocolName, targetSurvey, roster)
	if err != nil {
		return nil, err
	}
	shufflingTimeExec := time.Since(start)

	shufflingResult := <-pi.(*protocols.ShufflingProtocol).FeedbackChannel

	shufflingTimeExec += pi.(*protocols.DeterministicTaggingProtocol).ExecTime
	shufflingTimeCommun := time.Since(start) - shufflingTimeExec

	if shufflingTimeCommun < 0 {
		shufflingTimeCommun = 0
	}

	s.TR.AggRequestTimeExec += shufflingTimeExec
	s.TR.AggRequestTimeCommun += shufflingTimeCommun

	return shufflingResult, nil
}

// KeySwitchingPhase performs the switch to the querier's key on the currently aggregated data.
func (s *Service) KeySwitchingPhase(targetSurvey SurveyID, roster *onet.Roster) ([]lib.FilteredResponse, error) {
	start := time.Now()
	pi, err := s.StartProtocol(protocols.KeySwitchingProtocolName, targetSurvey, roster)
	if err != nil {
		return nil, err
	}
	keySwitchedAggregatedResponses := <-pi.(*protocols.KeySwitchingProtocol).FeedbackChannel

	// *(nbr of servers) because this protocol happens sequentially
	keySTimeExec := pi.(*protocols.KeySwitchingProtocol).ExecTime * time.Duration(len(roster.List))
	keySTimeCommun := time.Since(start) - keySTimeExec

	if keySTimeCommun < 0 {
		keySTimeCommun = 0
	}

	s.TR.AggRequestTimeExec += keySTimeExec
	s.TR.AggRequestTimeCommun += keySTimeCommun

	return keySwitchedAggregatedResponses, nil
}

// Support functions
//______________________________________________________________________________________________________________________

func checkDDTSecrets(path string, id network.Address) (abstract.Scalar, error) {
	var fileHandle *os.File
	var err error
	defer fileHandle.Close()

	if _, err = os.Stat(path); os.IsNotExist(err) {
		fileHandle, err = os.Create(path)

		secret := network.Suite.Scalar().Pick(random.Stream)
		b, err := secret.MarshalBinary()

		if err != nil {
			return nil, err
		}

		fmt.Fprintf(fileHandle, "%s %s\n", id.String(), base64.StdEncoding.EncodeToString(b))

		return secret, nil

	}

	fileHandle, err = os.Open(path)

	if err != nil {
		return nil, err
	}

	scanner := bufio.NewScanner(fileHandle)
	for scanner.Scan() {
		line := scanner.Text()
		tokens := strings.Split(line, " ")

		if id.String() == tokens[0] {
			secret := network.Suite.Scalar()

			b, err := base64.StdEncoding.DecodeString(tokens[1])

			if err != nil {
				return nil, err
			}

			err = secret.UnmarshalBinary(b)

			if err != nil {
				return nil, err
			}

			return secret, nil
		}
	}

	fileHandle.Close()

	secret := network.Suite.Scalar().Pick(random.Stream)
	b, err := secret.MarshalBinary()

	if err != nil {
		return nil, err
	}

	fileHandle, err = os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	fmt.Fprintf(fileHandle, "%s %s\n", id.String(), base64.StdEncoding.EncodeToString(b))

	return secret, nil
}
