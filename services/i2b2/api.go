package serviceI2B2

import (
	"github.com/lca1/unlynx/lib"
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/crypto.v0/config"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/dedis/onet.v1/network"
	"time"
)

// API represents a client with the server to which he is connected and its public/private key pair.
type API struct {
	*onet.Client
	ClientID   string
	entryPoint *network.ServerIdentity
	public     abstract.Point
	private    abstract.Scalar
}

// NewUnLynxClient constructor of a client.
func NewUnLynxClient(entryPoint *network.ServerIdentity, clientID string) *API {
	keys := config.NewKeyPair(network.Suite)

	newClient := &API{
		Client:     onet.NewClient(ServiceName),
		ClientID:   clientID,
		entryPoint: entryPoint,
		public:     keys.Public,
		private:    keys.Secret,
	}
	return newClient
}

// Send Query
//______________________________________________________________________________________________________________________

// SendSurveyDpQuery creates a survey based on a set of entities (servers) and a survey description.
func (c *API) SendSurveyDpQuery(entities *onet.Roster, surveyGenID, surveyID SurveyID, clientPubKey abstract.Point, nbrDPs map[string]int64, proofs, appFlag bool, sum []string, count bool, where []lib.WhereQueryAttribute, predicate string, groupBy []string, data []lib.ProcessResponse, mode int64, sendingTime time.Time) (*SurveyID, lib.FilteredResponse, TimeResults, error) {
	log.Lvl1("Client", c.ClientID, "is creating a survey with General ID:", surveyGenID)

	var newSurveyID SurveyID

	sdq := SurveyDpQuery{
		SurveyGenID:  surveyGenID,
		SurveyID:     surveyID,
		Roster:       *entities,
		ClientPubKey: clientPubKey,
		MapDPs:       nbrDPs,
		QueryMode:    mode,
		Proofs:       proofs,
		AppFlag:      appFlag,

		// query statement
		Sum:       sum,
		Count:     count,
		Where:     where,
		Predicate: predicate,
		GroupBy:   groupBy,
		DpData:    data,

		// for simulations
		SendingTime: sendingTime,
	}

	resp := ServiceResult{}
	err := c.SendProtobuf(c.entryPoint, &sdq, &resp)
	if err != nil {
		return nil, resp.Results, TimeResults{}, err
	}

	return &newSurveyID, resp.Results, resp.TR, nil
}
