module github.com/ldsec/unlynx

go 1.14

require (
	github.com/BurntSushi/toml v0.3.1
	github.com/Knetic/govaluate v3.0.0+incompatible
	github.com/cpuguy83/go-md2man/v2 v2.0.0 // indirect
	github.com/fanliao/go-concurrentMap v0.0.0-20141114143905-7d2d7a5ea67b
	github.com/gorilla/websocket v1.4.1 // indirect
	github.com/montanaflynn/stats v0.6.3 // indirect
	github.com/r0fls/gostats v0.0.0-20180711082619-e793b1fda35c
	github.com/satori/go.uuid v1.2.0
	github.com/stretchr/testify v1.4.0
	github.com/urfave/cli v1.22.3
	go.dedis.ch/kyber/v3 v3.0.12
	go.dedis.ch/onet/v3 v3.1.1
	golang.org/x/crypto v0.0.0-20200302210943-78000ba7a073 // indirect
	golang.org/x/sys v0.0.0-20200302150141-5c8b2ff67527 // indirect
	golang.org/x/xerrors v0.0.0-20191204190536-9bdfabe68543
)

//replace go.dedis.ch/onet/v3 => ../../../go.dedis.ch/onet
