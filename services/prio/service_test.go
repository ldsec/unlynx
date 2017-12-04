package prio

import (
	"testing"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/log"
)

func TestServicePrio(t *testing.T) {
	//log.SetDebugVisible(3)
	local := onet.NewLocalTest()

	// generate 5 hosts, they don't connect, they process messages, and they
	// don't register the tree or entitylist
	_, el, _ := local.GenTree(5, false)
	defer local.CloseAll()

	client := NewPrioClient("TestClient")
	client2 := NewPrioClient("Client2")
	log.Lvl1("Secret value is ", client.secretValue)

	res,_ := client.SendRequest(el)
	client.ExecuteRequest(el,res)

	agg,_ := client.Aggregate(el,res)
	log.Lvl1("Agg is ",agg)

	res,_ = client2.SendRequest(el)
	client2.ExecuteRequest(el,res)


	agg,_ = client.Aggregate(el,res)
	log.Lvl1("Agg is ",agg)
}
