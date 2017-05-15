package serviceSkipchain_test

import (
	"testing"

	"github.com/JoaoAndreSa/MedCo/services/skipchain"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/log"
	"medblock/service/topology"
	"strconv"
)

func TestMain(m *testing.M) {
	log.MainTest(m)
}

//______________________________________________________________________________________________________________________
/// Test the creation of a new topology skipchain
func TestServiceCreateTopologySkipchain(t *testing.T) {
	log.LLvl1("***************************************************************************************************")
	log.SetDebugVisible(1)
	local := onet.NewLocalTest()

	// generate 3 hosts, they don't connect, they process messages, and they
	// don't register the tree or entitylist
	_, el, _ := local.GenTree(3, true)
	defer local.CloseAll()

	// Send a request to the service
	client := serviceSkipchain.NewTopologyClient(el.List[0], strconv.Itoa(0))

	data := topology.RandomData(1, 3, 4)
	cerr := client.SendTopologyCreationQuery(el, data)
	if cerr != nil {
		log.Fatal("While creating a topology skipchain", cerr)
	}
}
