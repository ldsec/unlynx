package prio

import (
	"gopkg.in/dedis/onet.v1/network"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/crypto.v0/abstract"
	"time"
	"math/big"
	"unlynx/prio_utils"
	"prio/share"
)

type API struct {
	*onet.Client
	ClientID   string
	secretValue *big.Int
	modulus *big.Int
}

// NewPrioClient constructor of a client.
func NewPrioClient(clientID string) *API {

	newClient := &API{
		Client:     onet.NewClient(ServiceName),
		ClientID:   clientID,
		secretValue: prio_utils.RandInt(share.IntModulus),
		modulus: share.IntModulus,
	}
	return newClient
}

func (c *API) SendRequest(entities *onet.Roster, sendingTime time.Time)(*big.Int, error) {

	numServer := len(entities.List)
	dataSplited := prio_utils.Share(c.modulus,numServer,c.secretValue)

	requests := prio_utils.ClientRequest(dataSplited,0)
	circuitConfig := make([]int,numServer)

	for i, _:= range requests {
		circuitConfig[i] = dataSplited[i].BitLen()
	}

	servList := entities.List
	resp := ServiceResult{}
	randomPoint := prio_utils.RandInt(c.modulus)

	//send what to who still need to be precised here
	for i:=0;i<len(servList) ;i++  {
		dsc := DataSentClient{
			request:requests[i],
			circuitConfig: circuitConfig,
			randomPoint:randomPoint,
		}
		err := c.SendProtobuf(servList[i],&dsc,&resp)
		if err != nil {
			return resp.Results, err
		}
	}
	return resp.Results, nil

	}
