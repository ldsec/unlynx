package timedataunlynx_test

import (
	"testing"

	"github.com/lca1/unlynx/simul/test_data/time_data"
)

const filenameRead = "../shuffling+ddt.csv"
const filenameWrite = "result.txt"
const filenameToml = "../../runfiles/shuffling+ddt.toml"

/*var flags = []string{"bf", "depth", "rounds", "runwait", "servers", "\n",
"Shuffling(START)", "Shuffling(DISPATCH)", "Shuffling(START-noProof)", "Shuffling(DISPATCH-noProof)", "Shuffling(START-Proof)", "Shuffling(DISPATCH-Proof)", "ShufflingPhase", "\n",
"Rerandomization-2xADDS", "Rerandomization-2xMULTIS", "\n",
"DetTagging(START)", "DetTagging(DISPATCH)", "DetTagging1(DISPATCH)", "TaggingPhase", "\n",
"ShufflingPhase+TaggingPhase", "\n",
"CollectiveAggregation(Aggregation)", "CollectiveAggregation(ascendingAggregation)", "CollectiveAggregation(Proof-1stPart)", "CollectiveAggregation(Proof-2ndPart)", "AggregationPhase", "\n",
"LocalAggregation(PROTOCOL)", "LocalAggregation(PROOFS)", "\n",
"KeySwitching(START)", "KeySwitching(DISPATCH)", "KeySwitchingPhase", "\n",
"SendingData", "ServerLocalAggregation", "ClientEncryption", "IndividualSendSurveyResults", "IndividualNewUnLynxClient", "\n", "\n",
"Simulation", "Sending", "Receiving", "Shuffling(SIMULATION)", "MethodSending", "MethodReceiving", "SendingBytes", "sendingKey", "receivingKey", "KeySwitching(SIMULATION)", "\n", "\n",
"KeySwitchingVerif", "DetTagVerif", "DetTagAddVerif", "LocalAggrVerif", "ShufflingVerif", "CollectiveAggrVerif", "AddRmServer(PROTOCOL)", "AddRmServer(PROOFS)", "AddRmServer(PROOFSVerif)"}*/

var flags = []string{"bf", "depth", "rounds", "runwait", "servers", "\n",
	"ShufflingPlusDDT(SIMULATION)", "ShufflingPlusDDT(DummyDataGenerationAndEncryption)", "ShufflingPlusDDT(Precomputation)", "ShufflingPlusDDT(ReadData)", "ShufflingPlusDDT(Step1-Shuffling)", "ShufflingPlusDDT(Step2-DDTAddition)", "ShufflingPlusDDT(Step3-DDT)", "ShufflingPlusDDT(SendData)", "ShufflingPlusDDT(PrepareResult)",
}

func TestReadTomlSetup(t *testing.T) {
	t.Skip()
	timedataunlynx.ReadTomlSetup(filenameToml, 0)
}

func TestReadDataToCSVFile(t *testing.T) {
	t.Skip()
	timedataunlynx.ReadDataFromCSVFile(filenameRead, flags)
}

func TestWriteDataFromCSVFile(t *testing.T) {
	t.Skip()
	testTimeData := timedataunlynx.ReadDataFromCSVFile(filenameRead, flags)

	timedataunlynx.CreateCSVFile(filenameWrite)
	for i := 0; i < len(testTimeData[flags[0]]); i++ {
		setup := timedataunlynx.ReadTomlSetup(filenameToml, i)
		timedataunlynx.WriteDataFromCSVFile(filenameWrite, flags, testTimeData, i, setup)
	}
}
