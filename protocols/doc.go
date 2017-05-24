// Package protocols contains the code for the unlynx protocols.
// UnLynx stands for medical cothority and more precisely for privacy-preserving medical data sharing
// using a cothority. We use medical data and more precisely medical surveys as a working example
// but we intend to create a more general framework which would be a decentralized database containing
// any kind of data that could be queried in a privacy-preserving way.
//
// This protocols package contains the protocols which permit to do a private survey.
// Once the servers (nodes) of the cothority have gathered the client responses encrypted with El-Gamal
// under the collective public key of the cothority (constructed with the secret of each node in order to have
// strongest-link security),
// the nodes can:
//	- transform an El-Gamal ciphertext encrypted under one key to another key without decrypting it
//	  (key_switching_protocol)
//	- collectively aggregate their local results (private_aggregate_protocol)
//	- participates in the deterministic distributed tag creation (deterministic_tagging_protocol)
//	- participates in the Shuffling protocol (shuffling_protocol)
//	- a server leyving or joining the cothority can change data encryption to adapt to new collectiv key
//	  by using addrm_server_protocol
package protocols
