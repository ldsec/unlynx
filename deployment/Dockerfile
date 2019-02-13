FROM golang:1.11 as build

# build time environment variables
ENV UNLYNX_REPO="github.com/lca1/unlynx"

# get maximum of dependencies and cache them
RUN go get -v -d gopkg.in/urfave/cli.v1/... && \
    go get -v -d github.com/Knetic/govaluate/... && \
    go get -v -d github.com/btcsuite/goleveldb/... && \
    go get -v -d github.com/r0fls/gostats/... && \
    go get -v -d github.com/fanliao/go-concurrentMap/...

COPY ./ /go/src/$UNLYNX_REPO

# TODO: this should be removed when onet and kyber get updated to v3
# to keep everythin stable we revert to a fixed commit of the onet and kyber libraries
WORKDIR  /go/src/github.com/dedis
RUN git clone https://github.com/dedis/onet.git && \
    git clone https://github.com/dedis/kyber.git

WORKDIR  /go/src/github.com/dedis/onet
RUN git checkout 5796104343ef247e2eed58e573f68c566db2136f

WORKDIR  /go/src/github.com/dedis/kyber
RUN git checkout f55fec5463cda138dfc7ff15e4091d12c4ddcbfe
#-------------------------------------------------------------------------------------

# get remaining dependencies, compile all sources and produce executables
# CGO_ENABLED=0 in order to be able to run from alpine
WORKDIR /go/src/$UNLYNX_REPO
RUN go get -v -d ./... && \
    CGO_ENABLED=0 go build -v ./... && \
    CGO_ENABLED=0 go install -v ./...

EXPOSE 2000 2001
ENTRYPOINT ["simul"]
