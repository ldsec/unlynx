package serviceI2B2

import (
	"github.com/lca1/unlynx/lib"
	"gopkg.in/dedis/crypto.v0/abstract"
	"gopkg.in/dedis/crypto.v0/config"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/dedis/onet.v1/network"
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

// SendSurveyDDTQueryTerms send the encrypted query terms and DDT tags those terms (the array of terms is ordered).
func (c *API) SendSurveyDDTQueryTerms(entities *onet.Roster, surveyID SurveyID, terms lib.CipherVector, proofs bool) (*SurveyID, []lib.GroupingKey, TimeResults, error) {
	log.Lvl1("Client", c.ClientID, "is creating a survey with ID:", surveyID)

	sdq := SurveyDDTQueryTerms{
		SurveyID: surveyID,
		Roster:   *entities,
		Proofs:   proofs,

		// query parameters to DDT
		Terms: terms,

		IntraMessage: false,
	}

	resp := ServiceResultDDT{}
	err := c.SendProtobuf(c.entryPoint, &sdq, &resp)
	if err != nil {
		return nil, resp.Results, TimeResults{}, err
	}
	return &surveyID, resp.Results, resp.TR, nil
}
