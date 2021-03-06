package protocolsunlynx

import (
	"go.dedis.ch/onet/v3"
	"go.dedis.ch/onet/v3/log"
)

// DROProtocolName is the registered name for the differential privacy protocol.
const DROProtocolName = "DRO"

func init() {
	_, err := onet.GlobalProtocolRegister(DROProtocolName, func(tn *onet.TreeNodeInstance) (onet.ProtocolInstance, error) { return nil, nil })
	log.ErrFatal(err, "Failed to register the <DRO> protocol:")
}
