FROM golang:1.12 as build

COPY ./ /src

# get dependencies, compile all sources and produce executables
# CGO_ENABLED=0 in order to be able to run from alpine
WORKDIR /src
RUN go get -v -d ./... && \
    CGO_ENABLED=0 go build -v ./... && \
    CGO_ENABLED=0 go install -v ./... && \
    CGO_ENABLED=0 go build -o /go/bin/unlynx /src/app/*.go

EXPOSE 2000 2001
ENTRYPOINT ["unlynx"]