FROM golang:1.8

# environment variables
ENV UNLYNX_REPO="github.com/lca1/unlynx" \
    UNLYNX_REPO_BRANCH="newI2B2"

# get maximum of dependencies and cache them
RUN go get -v -d gopkg.in/dedis/onet.v1/... && \
    go get -v -d gopkg.in/dedis/crypto.v0/... && \
    go get -v -d gopkg.in/urfave/cli.v1/... && \
    go get -v -d github.com/Knetic/govaluate/... && \
    go get -v -d github.com/btcsuite/goleveldb/... && \
    go get -v -d github.com/r0fls/gostats/... && \
    go get -v -d github.com/fanliao/go-concurrentMap/...

# get sources and switch branch
WORKDIR /go/src/$UNLYNX_REPO
RUN git clone https://$UNLYNX_REPO.git . && \
    git checkout $UNLYNX_REPO_BRANCH

# get remaining dependencies, compile and install unlynxI2B2 binary, and make it available in the shared folder
WORKDIR app/i2b2
RUN go get -d ./... && \
    go build -i -o unlynxI2B2 ./...

# conf and run
VOLUME /opt/configuration
ENTRYPOINT ["sh", "-c", "./unlynxI2B2 -d 1 server -c /opt/configuration/private.toml"]
# TODO switch for prod:
# TODO: debug option to modify
# TODO: logs to put in unlynx folder (now: stdin)
# TODO: key generation handling (docker exec? or get the unlynx volume?)
