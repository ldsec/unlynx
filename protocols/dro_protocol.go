package protocols

import (
	"gopkg.in/dedis/onet.v1"
)

// DROProtocolName is the registered name for the differential privacy protocol.
const DROProtocolName = "DRO"

func init() {
	onet.GlobalProtocolRegister(DROProtocolName, func(tn *onet.TreeNodeInstance) (onet.ProtocolInstance, error) { return nil, nil })
}
