package timedata_test

import (
	"testing"

	"github.com/lca1/unlynx/simul/test_data/time_data"
)

const filenameRead = "../service_unlynx.csv"
const filenameWrite = "result.txt"
const filenameToml = "../../runfiles/unlynx_default.toml"

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
	t.Skip()
	timedata.ReadTomlSetup(filenameToml, 0)
}

func TestReadDataToCSVFile(t *testing.T) {
	t.Skip()
	timedata.ReadDataFromCSVFile(filenameRead, flags)
}

func TestWriteDataFromCSVFile(t *testing.T) {
	t.Skip()
	testTimeData := timedata.ReadDataFromCSVFile(filenameRead, flags)

	timedata.CreateCSVFile(filenameWrite)
	for i := 0; i < len(testTimeData[flags[0]]); i++ {
		setup := timedata.ReadTomlSetup(filenameToml, i)
		timedata.WriteDataFromCSVFile(filenameWrite, flags, testTimeData, i, setup)
	}
}
