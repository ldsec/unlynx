package protocolsunlynx

import (
	"go.dedis.ch/onet/v3"
)

// DROProtocolName is the registered name for the differential privacy protocol.
const DROProtocolName = "DRO"

func init() {
	onet.GlobalProtocolRegister(DROProtocolName, func(tn *onet.TreeNodeInstance) (onet.ProtocolInstance, error) { return nil, nil })
}
