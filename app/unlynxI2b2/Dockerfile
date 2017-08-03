# Docker file, deploy unlynxI2b2 using the source code in the parent folder, run with:
# docker run -v "$(pwd)"/app/unlynxI2b2/test/srv1:/unlynx -p 2010-2011:2000-2001 -it --rm --name unlynxi2b2-dev-srv1 unlynxi2b2

FROM golang:1.8

# get maximum of dependencies and cache them
RUN go get -v -d gopkg.in/dedis/onet.v1/... && \
    go get -v -d gopkg.in/dedis/crypto.v0/... && \
    go get -v -d gopkg.in/urfave/cli.v1/... && \
    go get -v -d github.com/Knetic/govaluate/... && \
    go get -v -d github.com/btcsuite/goleveldb/... && \
    go get -v -d github.com/r0fls/gostats/... && \
    go get -v -d github.com/fanliao/go-concurrentMap/...

# copy unlynx sources
ENV UNLYNX_PROJECT_PATH "github.com/lca1/unlynx"
WORKDIR /go/src/$UNLYNX_PROJECT_PATH
COPY . .

# get remaining dependencies, compile and install unlynxI2b2 binary
WORKDIR app/unlynxI2b2
RUN go get -v -d ./...
RUN go install -v ./...

# conf and run
EXPOSE 2000
VOLUME /unlynx
WORKDIR /unlynx
ENTRYPOINT ["unlynxI2b2", "-d", "5", "server", "-c", "/unlynx/private.toml"]
# TODO switch for prod:
# TODO: remove unlynx volume? (contains private key)
# TODO: debug option to modify
# TODO: logs to put in unlynx folder (now: stdin)
# TODO: key generation handling (docker exec? or get the unlynx volume?)
