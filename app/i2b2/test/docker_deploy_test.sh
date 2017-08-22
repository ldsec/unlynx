#!/bin/bash

dockerRun(){
    # $1 should be a number
    docker run -d -v "$(pwd)/app/i2b2/test/srv$1":/unlynx --net="host" -it --rm --name "unlynxi2b2-dev-srv${1}" unlynxi2b2
    #docker run -d -v "$(pwd)/app/i2b2/test/srv$1":/unlynx -p $2  -it --rm --name "unlynxi2b2-dev-srv${1}" unlynxi2b2
    #docker run -d -v "$(pwd)/app/i2b2/test/srv$1":/unlynx -p "20${1}0-20${1}1:2000-2001" -it --rm --name "unlynxi2b2-dev-srv${1}" unlynxi2b2
    #docker run -v "$(pwd)"/app/i2b2/test/srv1:/unlynx -p 2010-2011:2000-2001 -it --rm --name unlynxi2b2-dev-srv1 unlynxi2b2
}

dockerStop(){
    # $1 should be a number
    docker stop "unlynxi2b2-dev-srv${1}"
}

PROJECT_DIR="$GOPATH/src/github.com/lca1/unlynx/app/i2b2"
cd "$PROJECT_DIR"
docker build -t unlynxi2b2 .

dockerStop "1"
dockerStop "3"
dockerStop "5"

#dockerRun "1"
#dockerRun "3"
#dockerRun "5"
