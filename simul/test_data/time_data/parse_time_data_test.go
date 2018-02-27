package timedata_test

import (
	"testing"

	"github.com/lca1/unlynx/simul/test_data/time_data"
)

const filename_read = "../service_unlynx.csv"
const filename_write = "result.txt"
const filename_toml = "../../runfiles/unlynx_default.toml"

var flags = []string{"bf", "depth", "rounds", "runwait", "servers", "\n",
	"Shuffling(START)", "Shuffling(DISPATCH)", "Shuffling(START-noProof)", "Shuffling(DISPATCH-noProof)", "Shuffling(START-Proof)", "Shuffling(DISPATCH-Proof)", "ShufflingPhase", "\n",
	"Rerandomization-2xADDS", "Rerandomization-2xMULTIS", "\n",
	"DetTagging(START)", "DetTagging(DISPATCH)", "DetTagging1(DISPATCH)", "TaggingPhase", "\n",
	"ShufflingPhase+TaggingPhase", "\n",
	"CollectiveAggregation(Aggregation)", "CollectiveAggregation(ascendingAggregation)", "CollectiveAggregation(Proof-1stPart)", "CollectiveAggregation(Proof-2ndPart)", "AggregationPhase", "\n",
	"LocalAggregation(PROTOCOL)", "LocalAggregation(PROOFS)", "\n",
	"KeySwitching(START)", "KeySwitching(DISPATCH)", "KeySwitchingPhase", "\n",
	"SendingData", "ServerLocalAggregation", "ClientEncryption", "IndividualSendSurveyResults", "IndividualNewUnLynxClient", "\n", "\n",
	"Simulation", "Sending", "Receiving", "Shuffling(SIMULATION)", "MethodSending", "MethodReceiving", "SendingBytes", "sendingKey", "receivingKey", "KeySwitching(SIMULATION)", "\n", "\n",
	"KeySwitchingVerif", "DetTagVerif", "DetTagAddVerif", "LocalAggrVerif", "ShufflingVerif", "CollectiveAggrVerif", "AddRmServer(PROTOCOL)", "AddRmServer(PROOFS)", "AddRmServer(PROOFSVerif)"}

func TestReadTomlSetup(t *testing.T) {
	timedata.ReadTomlSetup(filename_toml, 0)
}

func TestReadDataToCSVFile(t *testing.T) {
	timedata.ReadDataFromCSVFile(filename_read, flags)
}

func TestWriteDataFromCSVFile(t *testing.T) {
	test_time_data := timedata.ReadDataFromCSVFile(filename_read, flags)

	timedata.CreateCSVFile(filename_write)
	for i := 0; i < len(test_time_data[flags[0]]); i++ {
		setup := timedata.ReadTomlSetup(filename_toml, i)
		timedata.WriteDataFromCSVFile(filename_write, flags, test_time_data, i, setup)
	}
}
