#!/usr/bin/env bash

env GOOS=linux GOARCH=amd64 go install ./...
mv "$GOPATH"/bin/i2b2 "$GOPATH"/bin/unlynxI2b2
