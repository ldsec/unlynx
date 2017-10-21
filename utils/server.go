package utils

import (

)


func NewRequest(args *NewRequestArgs, reply *NewRequestReply) error {
	// Add request to queue
	/*r, err := decryptRequest(p.Index(), &args.RequestID, &args.Ciphertext)
	if err != nil {
		log.Print("Could not decrypt insert args")
		return err
	}

	dstServer := int(args.RequestID[0]) % p.Tree().Size()

	s.pendingMutex.RLock()
	exists := s.pending[args.RequestID] != nil
	s.pendingMutex.RUnlock()

	if exists {
		log.Print(s.pending[args.RequestID])
		log.Print("Error: Key collision! Ignoring bogus request.")
		return nil
	}

	//status := new(RequestStatus)
	//status.check = p.pool[dstServer].get()
	//status.check.SetReq(r)
	*/
	return nil

}
