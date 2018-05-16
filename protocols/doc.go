// Package protocolsunlynx contains the code for the unlynx protocols.
//
// This protocols package contains the protocols which permit to run different operations on ciphertexts and the cothority
// Once the servers (nodes) of the cothority have gathered the client responses encrypted with El-Gamal
// under the collective public key of the cothority (constructed with the secret of each node in order to have
// strongest-link security),
// the nodes can:
//	- a server leaving or joining the cothority can change data encryption to adapt to new collective key
//	  (addrm_server_protocol)
//	- collectively aggregate their local results (collective_aggregate_protocol)
//	- participates in the deterministic distributed tag creation (deterministic_tagging_protocol)
//	- transform an ciphertext encrypted under one key to another key without decrypting it (key_switching_protocol)
//	- participates in the shuffle and rerandomization of a list of ciphertext (shuffling_protocol)
package protocolsunlynx
