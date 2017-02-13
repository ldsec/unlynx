package services

import (
	"strconv"

	"github.com/JoaoAndreSa/MedCo/lib"
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/crypto.v0/config"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/dedis/onet.v1/network"
)

// API represents a client with the server to which he is connected and its public/private key pair.
type API struct {
	*onet.Client
	entryPoint        *network.ServerIdentity
	localClientNumber int64
	public            abstract.Point
	private           abstract.Scalar
}

var localClientCounter = int64(0)

// NewMedcoClient constructor of a client.
func NewMedcoClient(entryPoint *network.ServerIdentity) *API {
	keys := config.NewKeyPair(network.Suite)
	newClient := &API{
		Client:            onet.NewClient(ServiceName),
		entryPoint:        entryPoint,
		localClientNumber: localClientCounter,
		public:            keys.Public,
		private:           keys.Secret,
	}

	localClientCounter++
	return newClient
}

// Send Query
//______________________________________________________________________________________________________________________

// SendSurveyCreationQuery creates a survey based on a set of entities (servers) and a survey description.
func (c *API) SendSurveyCreationQuery(entities *onet.Roster, surveyGenID, surveyID lib.SurveyID, surveyDescription lib.SurveyDescription, proofs bool, appFlag bool, querySubject []lib.ClientResponse, clientPubKey abstract.Point, dataToProcess []lib.ClientResponse, nbrDPs map[string]int64, aggregationTotal int64) (*lib.SurveyID, lib.ClientResponse, error) {
	log.Lvl1(c, "is creating a survey with general id: ", surveyGenID)

	var newSurveyID lib.SurveyID
	var results lib.ClientResponse

	// if Unlynx normal use
	if dataToProcess == nil {
		resp := ServiceResponse{}
		err := c.SendProtobuf(c.entryPoint, &SurveyCreationQuery{SurveyGenID: &surveyGenID, SurveyID: &surveyID, Roster: *entities, SurveyDescription: surveyDescription, Proofs: proofs, AppFlag: appFlag, QuerySubject: querySubject, ClientPubKey: clientPubKey, DataToProcess: dataToProcess, NbrDPs: nbrDPs, AggregationTotal: aggregationTotal}, &resp)
		if err != nil {
			return nil, lib.ClientResponse{}, err
		}

		log.LLvl1(c, " successfully created the survey with ID ", resp.SurveyID)
		newSurveyID = resp.SurveyID

	} else {
		// i2b2 compliant version
		resp := SurveyResultResponse{}
		err := c.SendProtobuf(c.entryPoint, &SurveyCreationQuery{SurveyGenID: &surveyGenID, SurveyID: &surveyID, Roster: *entities, SurveyDescription: surveyDescription, Proofs: proofs, AppFlag: appFlag, QuerySubject: querySubject, ClientPubKey: clientPubKey, DataToProcess: dataToProcess, NbrDPs: nbrDPs, AggregationTotal: aggregationTotal}, &resp)
		if err != nil {
			return nil, lib.ClientResponse{}, err
		}

		results = resp.Results[0]
	}
	return &newSurveyID, results, nil
}

// SendSurveyResponseQuery handles the encryption and sending of DP responses
func (c *API) SendSurveyResponseQuery(surveyID lib.SurveyID, clearClientResponses []lib.ClientClearResponse, groupKey abstract.Point, dataRepetitions int) error {
	log.LLvl1(c, " sends a result for survey ", surveyID)
	var err error

	s := EncryptDataToSurvey(c.String(), surveyID, clearClientResponses, groupKey, dataRepetitions)

	resp := ServiceResponse{}
	err = c.SendProtobuf(c.entryPoint, s, &resp)

	if err != nil {
		log.Fatal("Error while sending data")

	}

	return err
}

// SendGetSurveyResultsQuery to get the result from associated server and decrypt the response using its private key.
func (c *API) SendGetSurveyResultsQuery(surveyID lib.SurveyID) (*[][]int64, *[][]int64, *[][]int64, error) {
	log.LLvl1(c, " asks for the results of the survey ", surveyID)
	resp := SurveyResultResponse{}
	err := c.SendProtobuf(c.entryPoint, &SurveyResultsQuery{surveyID, c.public}, &resp)
	if err != nil {
		return nil, nil, nil, err
	}

	log.LLvl1(c, " got the survey result from ", c.entryPoint)

	grpClear := make([][]int64, len(resp.Results))
	grp := make([][]int64, len(resp.Results))
	aggr := make([][]int64, len(resp.Results))
	for i, res := range resp.Results {
		grpClear[i] = lib.UnKey(res.GroupingAttributesClear)
		grp[i] = lib.DecryptIntVector(c.private, &res.ProbaGroupingAttributesEnc)
		aggr[i] = lib.DecryptIntVector(c.private, &res.AggregatingAttributes)
	}
	return &grpClear, &grp, &aggr, nil
}

// Helper Functions
//______________________________________________________________________________________________________________________

// EncryptDataToSurvey is used to encrypt client responses with the collective key
func EncryptDataToSurvey(name string, surveyID lib.SurveyID, clearClientResponses []lib.ClientClearResponse, groupKey abstract.Point, dataRepetitions int) *SurveyResponseQuery {
	nbrResponses := len(clearClientResponses)

	log.Lvl1(name, " responds with ", nbrResponses, " response(s)")

	var clientResponses []lib.ClientResponse
	clientResponses = make([]lib.ClientResponse, nbrResponses*dataRepetitions)

	wg := lib.StartParallelize(len(clearClientResponses))
	round := lib.StartTimer(name + "_ClientEncryption")

	for i, v := range clearClientResponses {
		if lib.PARALLELIZE {
			go func(i int, v lib.ClientClearResponse) {
				// dataRepetitions is used to make the simulations faster by using the same response multiple times
				// should be set to 1 if no repet
				i = i * dataRepetitions
				if i < len(clientResponses) {
					clientResponses[i] = lib.EncryptClientClearResponse(v, groupKey)

					for j := 0; j < dataRepetitions && j+i < len(clientResponses); j++ {
						clientResponses[i+j].GroupingAttributesClear = clientResponses[i].GroupingAttributesClear
						clientResponses[i+j].ProbaGroupingAttributesEnc = clientResponses[i].ProbaGroupingAttributesEnc
						clientResponses[i+j].AggregatingAttributes = clientResponses[i].AggregatingAttributes
					}
				}
				defer wg.Done()
			}(i, v)
		} else {
			clientResponses[i] = lib.EncryptClientClearResponse(v, groupKey)
		}

	}
	lib.EndParallelize(wg)
	lib.EndTimer(round)
	return &SurveyResponseQuery{SurveyID: surveyID, Responses: clientResponses}
}

// String permits to have the string representation of a client.
func (c *API) String() string {
	return "[Client-" + strconv.FormatInt(c.localClientNumber, 10) + "]"
}
