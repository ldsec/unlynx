FROM golang:1.11 as build

# build time environment variables
ENV UNLYNX_REPO="github.com/lca1/unlynx"

# get maximum of dependencies and cache them
RUN go get -v -d github.com/dedis/onet/... && \
    go get -v -d github.com/dedis/kyber/... && \
    go get -v -d gopkg.in/urfave/cli.v1/... && \
    go get -v -d github.com/Knetic/govaluate/... && \
    go get -v -d github.com/btcsuite/goleveldb/... && \
    go get -v -d github.com/r0fls/gostats/... && \
    go get -v -d github.com/fanliao/go-concurrentMap/...

COPY ./ /go/src/$UNLYNX_REPO

# get remaining dependencies, compile all sources and produce executables
# CGO_ENABLED=0 in order to be able to run from alpine
WORKDIR /go/src/$UNLYNX_REPO
RUN go get -v -d ./... && \
    CGO_ENABLED=0 go build -v ./... && \
    CGO_ENABLED=0 go install -v ./...

# -------------------------------------------
FROM golang:1.11-alpine as release

COPY --from=build /go/bin /go/bin

EXPOSE 2000 2001
ENTRYPOINT ["simul"]
