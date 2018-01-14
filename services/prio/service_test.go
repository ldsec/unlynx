package prio

import (
	"testing"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/log"
)

var nbHost = 5
var nbServ = 5

func TestServicePrio(t *testing.T) {
	//log.SetDebugVisible(3)
	local := onet.NewLocalTest()

	// generate 5 hosts, they don't connect, they process messages, and they
	// don't register the tree or entitylist
	_, el, _ := local.GenTree(nbServ, false)
	defer local.CloseAll()

	dataPro := make([]*API,nbHost)

	//init
	for i,_:= range dataPro  {
		dataPro[i] = NewPrioClient("DP"+string(i))
	}

	//log.Lvl1("Secret value is ", (client.secretValue[0].IntBits) ,"bits")

	for i,v:= range dataPro  {
		res,_ := v.SendRequest(el)
		v.ExecuteRequest(el,res)
		if(i==len(dataPro)-1) {
			final,_ := dataPro[i].Aggregate(el,res)
			log.Lvl1(final)
		}
	}


}
