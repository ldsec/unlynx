package serviceI2B2

import (
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/network"
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/crypto.v0/config"
	"github.com/JoaoAndreSa/MedCo/lib"
	"gopkg.in/dedis/onet.v1/log"
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
func (c *API) SendSurveyDpQuery(entities *onet.Roster, surveyGenID, surveyID SurveyID, clientPubKey abstract.Point, nbrDPs map[string]int64, proofs, appFlag bool, sum []string, count bool, where []lib.WhereQueryAttribute, predicate string, groupBy []string, data []lib.ProcessResponse, mode int64) (*SurveyID, lib.FilteredResponse, error) {
	log.Lvl1(c, "is creating a survey with general id: ", surveyGenID)

	var newSurveyID SurveyID
	var results lib.FilteredResponse

	sdq := SurveyDpQuery{
		SurveyGenID:  &surveyGenID,
		SurveyID:     &surveyID,
		Roster:       *entities,
		ClientPubKey: clientPubKey,
		NbrDPs:       nbrDPs,
		Proofs:       proofs,
		AppFlag:      appFlag,

		// query statement
		Sum:       sum,
		Count:     count,
		Where:     where,
		Predicate: predicate,
		GroupBy:   groupBy,
		DpData:	   data,
		QueryMode:  mode,
	}

	resp := ServiceResult{}
	err := c.SendProtobuf(c.entryPoint, &sdq, &resp)
	if err != nil {
		return nil, lib.FilteredResponse{}, err
	}
	//results = resp.Results[0]

	return &newSurveyID, results, nil
}

