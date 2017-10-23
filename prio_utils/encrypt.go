package prio_utils

import (
	"bytes"
	"encoding/gob"
	"golang.org/x/crypto/nacl/box"
	"github.com/henrycg/prio/utils"
	"crypto/rand"

)

func encryptRequest(myPublicKey, myPrivateKey *[32]byte,
	serverIdx int, query *ClientRequest) (ServerCiphertext, error) {
	var out ServerCiphertext
	serverPublicKey := utils.ServerBoxPublicKeys[serverIdx]
	var nonce [24]byte
	_, err := rand.Read(nonce[:])
	if err != nil {
		return out, err
	}

	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	err = enc.Encode(query)
	if err != nil {
		return out, err
	}

	out.Nonce = nonce
	out.Ciphertext = box.Seal(nil, buf.Bytes(), &nonce, serverPublicKey, myPrivateKey)

	return out, nil
}

