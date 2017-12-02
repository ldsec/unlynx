package prio

import (
	"gopkg.in/dedis/onet.v1"
	"math/big"
	"unlynx/prio_utils"
	"prio/share"
	"gopkg.in/dedis/onet.v1/log"
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

func (c *API) SendRequest(entities *onet.Roster)(string, error) {

	numServer := len(entities.List)
	dataSplited := prio_utils.Share(c.modulus,numServer,c.secretValue)

	requests := prio_utils.ClientRequest(dataSplited,0)
	circuitConfig := make([]int64,numServer)

	for i, _:= range requests {
		circuitConfig[i] = int64(dataSplited[i].BitLen())
	}

	// Is the list ordered ?
	servList := entities.List

	resp := ServiceResult{}
	randomPoint := prio_utils.RandInt(c.modulus).Bytes()

	//send what to who still need to be precised here
	for i:=0;i<len(servList) ;i++  {
		dsc := DataSentClient{
			Leader : servList[0],
			Roster:entities,
			Request:requests[i],
			CircuitConfig: circuitConfig,
			RandomPoint:randomPoint,
		}
		log.Lvl1(servList[i])
		log.Lvl1(dsc)
		err := c.SendProtobuf(servList[i],&dsc,&resp)

		if err != nil {
			return resp.Results, err
		}

	}
	return resp.Results, nil
}

 func (c *API) ExecuteRequest(entities *onet.Roster,id string)(*big.Int, error) {
	 result := RequestResult{}
	 err := c.SendProtobuf(entities.List[0], &ExecRequest{id}, &result)

	 if err != nil {
		 return nil, err
	 }
	 return nil, nil
 }