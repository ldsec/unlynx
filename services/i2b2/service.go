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
	DDTparsingTime time.Duration // Total parsing time (i2b2 -> unlynx client)

	DDTRequestTimeExec    time.Duration // Total DDT (of the request) execution time
	DDTResquestTimeCommun time.Duration // Total DDT (of the request) communication time
}

// SurveyID unique ID for each survey.
type SurveyID string

// SurveyDDTRequestTerms is the message used trigger the DDT of the query parameters
type SurveyDDTRequestTerms struct {
	SurveyID SurveyID
	Roster   onet.Roster
	Proofs   bool

	Terms lib.CipherVector // query terms

	// message handling
	IntraMessage  bool
	MessageSource *network.ServerIdentity
}

// SurveyTag is the struct that we persist in the service that contains all the data for the DDT protocol
type SurveyTag struct {
	SurveyID      SurveyID
	Request       SurveyDDTRequestTerms
	SurveyChannel chan int // To wait for the survey to be created before the DDT protocol
}

// SurveyGenerated is used to ensure that all servers get the survey before starting the DDT protocol
type SurveyGenerated struct {
	SurveyID SurveyID
}

func castToSurvey(object interface{}, err error) SurveyTag {
	if err != nil {
		log.Error("Error reading map")
	}
	return object.(SurveyTag)
}

// MsgTypes defines the Message Type ID for all the service's intra-messages.
type MsgTypes struct {
	msgSurveyDDTRequestTerms network.MessageTypeID
	msgSurveyGenerated       network.MessageTypeID
}

var msgTypes = MsgTypes{}

func init() {
	onet.RegisterNewService(ServiceName, NewService)

	msgTypes.msgSurveyDDTRequestTerms = network.RegisterMessage(&SurveyDDTRequestTerms{})
	msgTypes.msgSurveyGenerated = network.RegisterMessage(&SurveyGenerated{})

	network.RegisterMessage(&ServiceResultDDT{})
}

// ServiceResultDDT will contain final results of the DDT of the query terms.
type ServiceResultDDT struct {
	Result []lib.GroupingKey
	TR     TimeResults // contains all the time measurements
}

// Service defines a service in unlynx with a survey.
type Service struct {
	*onet.ServiceProcessor

	MapSurveyTag *concurrent.ConcurrentMap
	Mutex        *sync.Mutex
	TR           TimeResults // contains all the time measurements
}

// NewService constructor which registers the needed messages.
func NewService(c *onet.Context) onet.Service {

	newUnLynxInstance := &Service{
		ServiceProcessor: onet.NewServiceProcessor(c),
		MapSurveyTag:     concurrent.NewConcurrentMap(),
		Mutex:            &sync.Mutex{},
	}

	if cerr := newUnLynxInstance.RegisterHandler(newUnLynxInstance.HandleSurveyDDTRequestTerms); cerr != nil {
		log.Error("Wrong Handler.", cerr)
	}

	c.RegisterProcessor(newUnLynxInstance, msgTypes.msgSurveyDDTRequestTerms)
	c.RegisterProcessor(newUnLynxInstance, msgTypes.msgSurveyGenerated)

	return newUnLynxInstance
}

// Process implements the processor interface and is used to recognize messages broadcasted between servers
func (s *Service) Process(msg *network.Envelope) {
	if msg.MsgType.Equal(msgTypes.msgSurveyDDTRequestTerms) {
		tmp := (msg.Msg).(*SurveyDDTRequestTerms)
		s.HandleSurveyDDTRequestTerms(tmp)
	} else if msg.MsgType.Equal(msgTypes.msgSurveyGenerated) {
		tmp := (msg.Msg).(*SurveyGenerated)
		s.HandleSurveyGenerated(tmp)
	}
}

// Request Handlers
//______________________________________________________________________________________________________________________

// HandleSurveyGenerated handles triggers the SurveyDDTChannel
func (s *Service) HandleSurveyGenerated(recq *SurveyGenerated) (network.Message, onet.ClientError) {
	(castToSurvey(s.MapSurveyTag.Get((string)(recq.SurveyID))).SurveyChannel) <- 1
	return nil, nil
}

// HandleSurveyDDTRequestTerms handles the reception of the query terms to be deterministically tagged
func (s *Service) HandleSurveyDDTRequestTerms(sdq *SurveyDDTRequestTerms) (network.Message, onet.ClientError) {

	// if this server is the one receiving the request from the client
	if !sdq.IntraMessage {
		log.Lvl1(s.ServerIdentity().String(), " received a SurveyDDTRequestTerms:", sdq.SurveyID)

		if len(sdq.Terms) == 0 {
			log.Lvl1(s.ServerIdentity(), " for survey", sdq.SurveyID, "has no data to det tag")
			return &ServiceResultDDT{}, nil
		}

		// initialize timers
		s.TR = TimeResults{DDTRequestTimeExec: 0, DDTResquestTimeCommun: 0}


		s.MapSurveyTag.Put((string)(sdq.SurveyID),
			SurveyTag{
				SurveyID:      sdq.SurveyID,
				Request:       *sdq,
				SurveyChannel: make(chan int, 100),
			})

		// signal the other nodes that they need to prepare to execute a DDT (no need to send the terms)
		err := services.SendISMOthers(s.ServiceProcessor, &sdq.Roster,
			&SurveyDDTRequestTerms{
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
			counter = counter - <-castToSurvey(s.MapSurveyTag.Get((string)(sdq.SurveyID))).SurveyChannel
		}

		deterministicTaggingResult, err := s.TaggingPhase(sdq.SurveyID)

		start := time.Now()

		if err != nil {
			log.Error("DDT error ", err)
		}

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

// Protocol Handlers
//______________________________________________________________________________________________________________________

// NewProtocol creates a protocol instance executed by all nodes
func (s *Service) NewProtocol(tn *onet.TreeNodeInstance, conf *onet.GenericConfig) (onet.ProtocolInstance, error) {
	tn.SetConfig(conf)

	var pi onet.ProtocolInstance
	var err error

	target := SurveyID(string(conf.Data))
	survey := castToSurvey(s.MapSurveyTag.Get(string(target)))

	switch tn.ProtocolName() {

	case protocols.DeterministicTaggingProtocolName:
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

	default:
		return nil, errors.New("Service attempts to start an unknown protocol: " + tn.ProtocolName() + ".")
	}

	return pi, nil
}

// StartProtocol starts a specific protocol (Pipeline, Shuffling, etc.)
func (s *Service) StartProtocol(name string, targetSurvey SurveyID) (onet.ProtocolInstance, error) {
	start := time.Now()

	tmp := castToSurvey(s.MapSurveyTag.Get((string)(targetSurvey)))
	tree := tmp.Request.Roster.GenerateNaryTreeWithRoot(2, s.ServerIdentity())

	tn := s.NewTreeNodeInstance(tree, tree.Root, name)

	conf := onet.GenericConfig{Data: []byte(string(targetSurvey))}

	pi, err := s.NewProtocol(tn, &conf)

	s.RegisterProtocolInstance(pi)

	s.TR.DDTRequestTimeExec = time.Since(start)

	go pi.Dispatch()
	go pi.Start()

	return pi, err
}

// Service Phases
//______________________________________________________________________________________________________________________

// TaggingPhase performs the private grouping on the currently collected data.
func (s *Service) TaggingPhase(targetSurvey SurveyID) ([]lib.ProcessResponseDet, error) {
	start := time.Now()
	pi, err := s.StartProtocol(protocols.DeterministicTaggingProtocolName, targetSurvey)
	if err != nil {
		return nil, err
	}

	deterministicTaggingResult := <-pi.(*protocols.DeterministicTaggingProtocol).FeedbackChannel

	s.TR.DDTRequestTimeExec += pi.(*protocols.DeterministicTaggingProtocol).ExecTime
	s.TR.DDTResquestTimeCommun = time.Since(start) - s.TR.DDTRequestTimeExec

	return deterministicTaggingResult, nil
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
