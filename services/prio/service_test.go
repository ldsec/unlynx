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
	log.Lvl1("Secret value is ", client.secretValue)

	res,_ := client.SendRequest(el)
	client.ExecuteRequest(el,res)

	log.Lvl1(client.Aggregate(el,res))

}
