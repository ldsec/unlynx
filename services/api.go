package services

import (
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
	clientID   string
	entryPoint *network.ServerIdentity
	public     abstract.Point
	private    abstract.Scalar
}

// NewMedcoClient constructor of a client.
func NewMedcoClient(entryPoint *network.ServerIdentity, clientID string) *API {
	keys := config.NewKeyPair(network.Suite)

	newClient := &API{
		Client:     onet.NewClient(ServiceName),
		clientID:   clientID,
		entryPoint: entryPoint,
		public:     keys.Public,
		private:    keys.Secret,
	}
	return newClient
}

// Send Query
//______________________________________________________________________________________________________________________

// SendSurveyCreationQuery creates a survey based on a set of entities (servers) and a survey description.
func (c *API) SendSurveyCreationQuery(entities *onet.Roster, surveyGenID, surveyID lib.SurveyID, sum []string, count bool, where []lib.WhereQueryAttribute, pred string, groupBy []string, clientPubKey abstract.Point, dataToProcess []lib.DpResponse, nbrDPs map[string]int64, queryMode int64, proofs, appFlag bool) (*lib.SurveyID, lib.FilteredResponse, error) {
	log.Lvl1(c, "is creating a survey with general id: ", surveyGenID)

	var newSurveyID lib.SurveyID
	var results lib.FilteredResponse
	// if Unlynx normal use
	if dataToProcess == nil {
		resp := ServiceResponse{}
		req := &lib.SurveyCreationQuery{SurveyGenID: &surveyGenID, SurveyID: &surveyID, Roster: *entities, Sum: sum, Count: count, Where: where, Pred: pred, GroupBy: groupBy, ClientPubKey: clientPubKey, DataToProcess: dataToProcess, NbrDPs: nbrDPs, QueryMode: queryMode, Proofs: proofs, AppFlag: appFlag}
		log.LLvlf1("QUERYYBEFORE %#v",req.GroupBy)
		err := c.SendProtobuf(c.entryPoint, req, &resp)
		if err != nil {
			return nil, lib.FilteredResponse{}, err
		}
		log.LLvl1(c, " successfully created the survey with ID ", resp.SurveyID)
		newSurveyID = resp.SurveyID

	} else {
		// i2b2 compliant version
		resp := SurveyResultResponse{}
		err := c.SendProtobuf(c.entryPoint, &lib.SurveyCreationQuery{SurveyGenID: &surveyGenID, SurveyID: &surveyID, Roster: *entities, Sum: sum, Count: count, Where: where, Pred: pred, GroupBy: groupBy, ClientPubKey: clientPubKey, DataToProcess: dataToProcess, NbrDPs: nbrDPs, QueryMode: queryMode, Proofs: proofs, AppFlag: appFlag}, &resp)
		if err != nil {
			return nil, lib.FilteredResponse{}, err
		}

		results = resp.Results[0]
	}
	return &newSurveyID, results, nil
}

// SendSurveyResponseQuery handles the encryption and sending of DP responses
func (c *API) SendSurveyResponseQuery(surveyID lib.SurveyID, clearClientResponses []lib.DpClearResponse, groupKey abstract.Point, dataRepetitions int, count bool) error {
	log.LLvl1(c, " sends a result for survey ", surveyID)
	var err error

	s := EncryptDataToSurvey(c.String(), surveyID, clearClientResponses, groupKey, dataRepetitions, count)

	resp := ServiceResponse{}
	err = c.SendProtobuf(c.entryPoint, s, &resp)

	if err != nil {
		log.Fatal("Error while sending data")

	}

	return err
}

// SendSurveyResultsQuery to get the result from associated server and decrypt the response using its private key.
func (c *API) SendSurveyResultsQuery(surveyID lib.SurveyID) (*[][]int64, *[][]int64, error) {
	log.LLvl1(c, " asks for the results of the survey ", surveyID)
	resp := SurveyResultResponse{}
	err := c.SendProtobuf(c.entryPoint, &SurveyResultsQuery{false, surveyID, c.public}, &resp)
	if err != nil {
		return nil, nil, err
	}

	log.LLvl1(c, " got the survey result from ", c.entryPoint)

	grp := make([][]int64, len(resp.Results))
	aggr := make([][]int64, len(resp.Results))
	for i, res := range resp.Results {
		//grpClear[i] = lib.UnKey(res.GroupingAttributesClear)
		grp[i] = lib.DecryptIntVector(c.private, &res.GroupByEnc)
		aggr[i] = lib.DecryptIntVector(c.private, &res.AggregatingAttributes)
	}
	return &grp, &aggr, nil
}

// Helper Functions
//______________________________________________________________________________________________________________________

// EncryptDataToSurvey is used to encrypt client responses with the collective key
func EncryptDataToSurvey(name string, surveyID lib.SurveyID, dpClearResponses []lib.DpClearResponse, groupKey abstract.Point, dataRepetitions int, count bool) *SurveyResponseQuery {
	nbrResponses := len(dpClearResponses)

	log.Lvl1(name, " responds with ", nbrResponses, " response(s)")

	var dpResponses []lib.DpResponseToSend
	dpResponses = make([]lib.DpResponseToSend, nbrResponses*dataRepetitions)

	wg := lib.StartParallelize(len(dpClearResponses))
	round := lib.StartTimer(name + "_ClientEncryption")

	for i, v := range dpClearResponses {
		if lib.PARALLELIZE {
			go func(i int, v lib.DpClearResponse) {
				// dataRepetitions is used to make the simulations faster by using the same response multiple times
				// should be set to 1 if no repet
				i = i * dataRepetitions
				if i < len(dpResponses) {
					dpResponses[i] = lib.EncryptDpClearResponse(v, groupKey, count)

					for j := 0; j < dataRepetitions && j+i < len(dpResponses); j++ {
						dpResponses[i+j].GroupByClear = dpResponses[i].GroupByClear
						dpResponses[i+j].GroupByEnc = dpResponses[i].GroupByEnc
						dpResponses[i+j].WhereClear = dpResponses[i].WhereClear
						dpResponses[i+j].WhereEnc = dpResponses[i].WhereEnc
						dpResponses[i+j].AggregatingAttributesClear = dpResponses[i].AggregatingAttributesClear
						dpResponses[i+j].AggregatingAttributesEnc = dpResponses[i].AggregatingAttributesEnc
					}
				}
				defer wg.Done()
			}(i, v)
		} else {
			dpResponses[i] = lib.EncryptDpClearResponse(v, groupKey, count)
		}

	}
	lib.EndParallelize(wg)
	lib.EndTimer(round)
	return &SurveyResponseQuery{SurveyID: surveyID, Responses: dpResponses}
}

// String permits to have the string representation of a client.
func (c *API) String() string {
	return "[Client-" + c.clientID + "]"
}
