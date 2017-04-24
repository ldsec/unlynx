#!/usr/bin/env bash

DBG_SHOW=1
# Debug-level for server
DBG_SRV=1
# Debug-level for client
DBG_CLIENT=1
# For easier debugging
BUILDDIR=$(pwd)
STATICDIR=test

. $GOPATH/src/gopkg.in/dedis/onet.v1/app/libtest.sh

main(){
    startTest
    test Build
    test ServerCfg
    test RunMedco
    clearSrv
}


#------- BUILD --------#
testBuild(){
    testOK dbgRun ./medco --help
}

build(){
    if [ "$STATICDIR" ]; then
        DIR=$STATICDIR
    else
        DIR=$(mktemp -d)
    fi

    rm -f $DIR/medco #to force compilation

    mkdir -p $DIR
    cd $DIR
    echo "Building in $DIR"

    if [ ! -x medco ]; then
        go build -o medco -a $BUILDDIR/*go
    fi

    for ((n=1; n <= $NBR*2; n+=2)) do
        srv=srv$n
        rm -rf $srv
        mkdir $srv
        cp $BUILDDIR/medco_test_data.txt $srv
        # cp $BUILDDIR/pre_compute_multiplications.gob $srv
    done
}


#------- SERVER CONFIGURATION --------#
testServerCfg(){
    for ((n=1; n <= $NBR*2; n+=2)) do
        runSrvCfg $n
        pkill -9 medco
        testFile srv$n/private.toml
    done
}

runSrvCfg(){
    echo -e "127.0.0.1:200$1\nMedco $1\n$(pwd)/srv$1\n" | ./medco server setup > $OUT
}


#------- CLIENT CONFIGURATION --------#
testRunMedco(){
    setupServers
    echo "Running Medco APP"
    runCl 1 run
}

setupServers(){
    rm -f group.toml
    for ((n=1; n <= $NBR*2; n+=2)) do
        srv=srv$n
        rm -f $srv/*
        runSrvCfg $n
        tail -n 4 $srv/public.toml >> group.toml

        cp $BUILDDIR/medco_test_data.txt $srv
        #cp $BUILDDIR/medco/pre_compute_multiplications.gob $srv

        runSrv $n &
    done


}

runSrv(){
    cd srv$1
    ../medco -d $DBG_SRV server -c private.toml
    cd ..
}

runCl(){
    G=group.toml
    shift
    echo "Running Client with $G $@"
    ./medco -d $DBG_CLIENT $@ -f $G -s "{s0, s1}" -w "{w0, 1, w1, 1}" -p "(v0 == v1 && v2 == v3)" -g "{g0, g1, g2}"
}


#------- CLEAR SERVERS --------#
clearSrv(){
    pkill -9 medco
}


#------- OTHER STUFF --------#
if [ "$1" == "-q" ]; then
  DBG_RUN=
  STATICDIR=
fi

main
