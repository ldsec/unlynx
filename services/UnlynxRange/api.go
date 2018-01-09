package UnlynxRange

import (
	"gopkg.in/dedis/onet.v1"

	"unlynx/prio_utils"
)

//data provider in prio represented as its secret value ID and modulus
type API struct {
	*onet.Client
	ClientID   string
	secretValue []int64
}

func NewUnlynxRangeClient(clientID string) *API {

	newClient := &API{
		Client:     onet.NewClient(ServiceName),
		ClientID:   clientID,
		secretValue:  []int64{2,16,154816,1,18946,48918896418965},
	}
	return newClient
}


func (c *API) SendRequest(entities *onet.Roster)(string, error) {
	numServer := len(entities.List)
	//dataSplited := prio_utils.Share(c.modulus,numServer,c.secretValue)

	//For the moment for almost all type, they are chosen randomly in function of the number of bits passed
	requests := prio_utils.ClientRequest(c.secretValue,numServer,0)

	//Conversion of field as protoBuf do not take int only int64
	circuitConfig := make([]ConfigByte,len(c.secretValue))
	for i:=0; i< len(c.secretValue) ; i++ {
		field := c.secretValue[i]
		linReg := make([]int64,0)
		for j:=0;j<len(field.LinRegBits);j++  {
			linReg = append(linReg, int64(field.LinRegBits[j]))
		}
		circuitConfig[i] = ConfigByte{Name:field.Name,IntBits:int64(field.IntBits),Type:int64(field.Type) ,LinRegBits:linReg,IntPow:int64(field.IntPow),CountMinBuckets:int64(field.CountMinBuckets),CountMinHashes:int64(field.CountMinHashes)}
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
		log.Lvl1(err)
		if err != nil {
			return resp.Results, err
		}

	}
	//return the id of the request in the concurrent map of service if successful
	return resp.Results, nil
}