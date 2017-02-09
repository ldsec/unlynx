package lib_i2b2_test

import (
	"encoding/hex"
	"os"
	"testing"

	"gopkg.in/dedis/onet.v1/log"
	"gopkg.in/dedis/onet.v1/network"
	"gopkg.in/dedis/onet.v1"
	"gopkg.in/dedis/crypto.v0/random"
	"github.com/JoaoAndreSa/MedCo/lib"
	"github.com/JoaoAndreSa/MedCo/lib/i2b2"
)

func TestCreateXMLforTestonI2B2(t *testing.T) {
	os.Remove("pre_compute_multiplications.gob")
	log.SetDebugVisible(2)
	local := onet.NewLocalTest()
	_, el, _ := local.GenTree(3, true)
	defer local.CloseAll()

	pubKeyStr := "8574c51103267a815281c88faa4c7ac2825d9c2372bd82c24023d375417354fd"
	pubKeyB, _ := hex.DecodeString(pubKeyStr)
	pubKey := network.Suite.Point()
	pubKey.UnmarshalBinary(pubKeyB)

	//create query responses
	cr1 := lib.ClientResponse{ProbaGroupingAttributesEnc: *lib.EncryptIntVector(pubKey, []int64{0, 1}), AggregatingAttributes: *lib.EncryptIntVector(pubKey, []int64{1})}
	cr2 := lib.ClientResponse{ProbaGroupingAttributesEnc: *lib.EncryptIntVector(pubKey, []int64{0, 1}), AggregatingAttributes: *lib.EncryptIntVector(pubKey, []int64{1})}
	cr3 := lib.ClientResponse{ProbaGroupingAttributesEnc: *lib.EncryptIntVector(pubKey, []int64{1, 0}), AggregatingAttributes: *lib.EncryptIntVector(pubKey, []int64{1})}
	cr4 := lib.ClientResponse{ProbaGroupingAttributesEnc: *lib.EncryptIntVector(pubKey, []int64{1, 1}), AggregatingAttributes: *lib.EncryptIntVector(pubKey, []int64{1})}
	cr5 := lib.ClientResponse{ProbaGroupingAttributesEnc: *lib.EncryptIntVector(pubKey, []int64{1, 1}), AggregatingAttributes: *lib.EncryptIntVector(pubKey, []int64{1})}
	cr6 := lib.ClientResponse{ProbaGroupingAttributesEnc: *lib.EncryptIntVector(pubKey, []int64{1, 1}), AggregatingAttributes: *lib.EncryptIntVector(pubKey, []int64{1})}
	cr7 := lib.ClientResponse{ProbaGroupingAttributesEnc: *lib.EncryptIntVector(pubKey, []int64{0, 0}), AggregatingAttributes: *lib.EncryptIntVector(pubKey, []int64{1})}
	cr8 := lib.ClientResponse{ProbaGroupingAttributesEnc: *lib.EncryptIntVector(pubKey, []int64{0, 0}), AggregatingAttributes: *lib.EncryptIntVector(pubKey, []int64{0})}
	data := []lib.ClientResponse{cr1, cr2, cr3, cr4, cr5, cr6, cr7, cr8}
	//create keys
	priKey := network.Suite.Scalar().Pick(random.Stream)
	priKeyB, _ := priKey.MarshalBinary()
	priKeyString := hex.EncodeToString(priKeyB)
	pubKey = network.Suite.Point().Mul(network.Suite.Point().Base(), priKey)
	pubKeyB, _ = pubKey.MarshalBinary()
	pubKeyString := hex.EncodeToString(pubKeyB)

	//write data in xml file
	tabStrData := make([][]string, len(cr1.ProbaGroupingAttributesEnc))
	for i := range tabStrData {
		col := make([]string, len(data))
		for j := range col {
			col[j] = hex.EncodeToString(data[j].ProbaGroupingAttributesEnc[i].ToBytes())
		}
		tabStrData[i] = col
	}
	lib_i2b2.CreateXMLData("123", pubKeyString, priKeyString, "3", "2", tabStrData, []string{"OR"}, "data.xml")

	//read xml data file
	lib_i2b2.ReadXMLData("data.xml", el.Aggregate)

}
