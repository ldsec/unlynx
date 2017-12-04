package prio

import (
	"gopkg.in/dedis/onet.v1"
	"math/big"
	"unlynx/prio_utils"
	"github.com/henrycg/prio/share"
)

//client in prio represented as its secret value ID and modulus
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
		secretValue: big.NewInt(285),
		modulus: share.IntModulus,
	}
	return newClient
}


//To send the data you split it and then send each request for 1 client submission to each server.
//ProtoBuf do not support big.Int, we need to transform to []byte and transfer like this, reconstruction done at
//server/
func (c *API) SendRequest(entities *onet.Roster)(string, error) {
	numServer := len(entities.List)
	dataSplited := prio_utils.Share(c.modulus,numServer,c.secretValue)


	requests := prio_utils.ClientRequest(dataSplited,0)

	circuitConfig := make([]int64,numServer)

	for i, _:= range requests {
		circuitConfig[i] = int64(dataSplited[i].BitLen())
	}

	// The list is ordered first == root
	servList := entities.List

	resp := ServiceResult{}
	randomPoint := prio_utils.RandInt(c.modulus).Bytes()

	for i:=0;i<len(servList) ;i++  {

		req := requests[i]
		shareA := req.TripleShare.ShareA.Bytes()
		shareB := req.TripleShare.ShareB.Bytes()
		shareC := req.TripleShare.ShareC.Bytes()
		hint := make([][]byte,0)
		for _,v := range req.Hint.Delta  {
			hint = append(hint,v.Bytes())
		}

		dsc := DataSentClient{
			Leader : servList[0],
			Roster:entities,
			CircuitConfig: circuitConfig,
			RandomPoint:randomPoint,
			ShareA:shareA,
			ShareB:shareB,
			ShareC:shareC,
			Hint:hint,
			Key:req.Hint.Key,
			RequestID:req.RequestID,
		}

		err := c.SendProtobuf(servList[i],&dsc,&resp)

		if err != nil {
			return resp.Results, err
		}

	}
	//return the id of the request in the concurrent map of service if successful
	return resp.Results, nil
}

//function to execute the client submission verification
func (c *API) ExecuteRequest(entities *onet.Roster,id string)(error) {
	result := RequestResult{}
	//send to the root the execution message
	for _,v := range entities.List {
		err := c.SendProtobuf(v, &ExecRequest{id}, &result)

		if err != nil {
			return  err
		}
	}
	return nil
}

func (c *API) Aggregate(entities *onet.Roster,id string)([]byte,error) {

	result := AggResult{}
	err := c.SendProtobuf(entities.List[0],&ExecAgg{id} , &result)

	if err != nil {
		return nil, err
	}

	return result.Result, nil
}