package serviceSkipchain_test

import (
	"testing"

	"bytes"
	"github.com/JoaoAndreSa/MedCo/services/skipchain"
	"github.com/stretchr/testify/require"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/dedis/onet.v1/network"
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
	genesis, cerr := client.SendTopologyCreationQuery(el, data)

	require.Nil(t, cerr)
	require.NotNil(t, genesis)

	result := topology.UnmarshalData(genesis)
	require.True(t, compareData(data.Data, result.Data)) //check the data is the same
}

//______________________________________________________________________________________________________________________
/// Test the addition of a new topology skipblock
func TestServiceUpdateTopologySkipchain(t *testing.T) {
	log.LLvl1("***************************************************************************************************")
	log.SetDebugVisible(1)
	local := onet.NewLocalTest()

	// generate 5 hosts, they don't connect, they process messages, and they
	// don't register the tree or entitylist
	_, el, _ := local.GenTree(5, true)
	defer local.CloseAll()

	// Send a request to the service
	client := serviceSkipchain.NewTopologyClient(el.List[0], strconv.Itoa(0))

	data := topology.RandomData(1, 3, 4)
	genesis, cerr := client.SendTopologyCreationQuery(el, data)
	if cerr != nil {
		log.Fatal("While creating a topology skipchain", cerr)
	}

	require.Nil(t, cerr)
	require.NotNil(t, genesis)

	result := topology.UnmarshalData(genesis)
	require.True(t, compareData(data.Data, result.Data)) //check the data is the same

	//1st Update
	sb, cerr := client.SendTopologyUpdateQuery(el, genesis, data)

	require.Nil(t, cerr)
	require.NotNil(t, sb)

	result = topology.UnmarshalData(sb)
	require.True(t, compareData(data.Data, result.Data)) //check the data is the same

	//2nd Update
	data = topology.RandomData(1, 5, 5)
	sb, cerr = client.SendTopologyUpdateQuery(el, genesis, data)

	require.Nil(t, cerr)
	require.NotNil(t, sb)

	result = topology.UnmarshalData(sb)
	require.True(t, compareData(data.Data, result.Data)) //check the data is the same

	//3nd Update - this is wrong (block data is nil)
	sb, cerr = client.SendTopologyUpdateQuery(el, genesis, nil)

	require.NotNil(t, cerr)

	//4th Update - this is wrong (previous sb is nil)
	sb, cerr = client.SendTopologyUpdateQuery(el, nil, data)

	require.NotNil(t, cerr)
}

func compareData(expected, result topology.DataTopology) bool {
	expectedB, err := network.Marshal(&expected)
	if err != nil {
		log.Fatal("While marshaling", err)
	}

	resultB, err := network.Marshal(&result)
	if err != nil {
		log.Fatal("While marshaling", err)
	}

	if bytes.Compare(expectedB, resultB) == 0 {
		return true
	} else {
		return false
	}

}
