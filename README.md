[![Build Status](https://travis-ci.org/lca1/unlynx.svg?branch=master)](https://travis-ci.org/LCA1/UnLynx) [![Go Report Card](https://goreportcard.com/badge/github.com/lca1/unlynx)](https://goreportcard.com/report/github.com/lca1/unlynx) [![Coverage Status](https://coveralls.io/repos/github/lca1/unlynx/badge.svg?branch=master)](https://coveralls.io/github/lca1/unlynx?branch=master)
# UnLynx 
UnLynx is a library for simulating a privacy-preserving data sharing tool. It offers a series of independent protocols that when combined offer a robust and safe way to share sensitive data (e.g., medical data).  

UnLynx is developed by lca1 (Laboratory for Communications and Applications in EPFL) in collaboration with DeDis (Laboratory for Decentralized and Distributed Systems).  

## Documentation

* The UnLynx library does an intensive use of [Overlay-network (ONet) library](https://github.com/dedis/onet)
* For more information regarding the underlying architecture please refer to the stable version of ONet `gopkg.in/dedis/onet.v1`
* To check the code organisation, have a look at [Layout](https://github.com/lca1/unlynx/wiki/Layout)
* For more information on how to run our services, simulations and apps, go to [Running UnLynx](https://github.com/lca1/unlynx/wiki/Running-UnLynx)

## Getting Started

To use the code of this repository you need to:

- Install [Golang](https://golang.org/doc/install)
- [Recommended] Install [IntelliJ IDEA](https://www.jetbrains.com/idea/) and the GO plugin
- Set [`$GOPATH`](https://golang.org/doc/code.html#GOPATH) to point to your workspace directory
- Add `$GOPATH/bin` to `$PATH`
- Git clone this repository to $GOPATH/src `git clone https://github.com/lca1/unlynx.git` or...
- go get repository: `go get github.com/lca1/unlynx`

## Version

The version in the `master`-branch is stable and has no incompatible changes.

## License

UnLynx is licensed under a End User Software License Agreement ('EULA') for non-commercial use. If you want to have more information, please contact us.

## Contact
You can contact any of the developers for more information or any other member of [lca1](http://lca.epfl.ch/people/lca1/):

* [David Froelicher](https://github.com/froelich) (PHD student) - david.froelicher@epfl.ch
* [Patricia Egger](https://github.com/pegger) (Security Consultant at Deloitte) - patricia.egger@epfl.ch
* [Joao Andre Sa](https://github.com/JoaoAndreSa) (Software Engineer) - joao.gomesdesaesousa@epfl.ch
* [Christian Mouchet](https://github.com/ChristianMct) (MSC student) - christian.mouchet@epfl.ch
