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
    test RunUnLynx
    clearSrv
}


#------- BUILD --------#
testBuild(){
    testOK dbgRun ./unlynx --help
}

build(){
    if [ "$STATICDIR" ]; then
        DIR=$STATICDIR
    else
        DIR=$(mktemp -d)
    fi

    rm -f $DIR/unlynx #to force compilation

    mkdir -p $DIR
    cd $DIR
    echo "Building in $DIR"

    if [ ! -x unlynx ]; then
        go build -o unlynx -a $BUILDDIR/*go
    fi

    for ((n=1; n <= $NBR*2; n+=2)) do
        srv=srv$n
        rm -rf $srv
        mkdir $srv
        cp $BUILDDIR/unlynx_test_data.txt $srv
        # cp $BUILDDIR/pre_compute_multiplications.gob $srv
    done
}


#------- SERVER CONFIGURATION --------#
testServerCfg(){
    for ((n=1; n <= $NBR*2; n+=2)) do
        runSrvCfg $n
        pkill -9 unlynx
        testFile srv$n/private.toml
    done
}

runSrvCfg(){
    echo -e "127.0.0.1:200$1\nUnLynx $1\n$(pwd)/srv$1\n" | ./unlynx server setup > $OUT
}


#------- CLIENT CONFIGURATION --------#
testRunUnLynx(){
    setupServers
    echo "Running UnLynx APP"
    runCl 1 run
}

setupServers(){
    rm -f group.toml
    for ((n=1; n <= $NBR*2; n+=2)) do
        srv=srv$n
        rm -f $srv/*
        runSrvCfg $n
        tail -n 4 $srv/public.toml >> group.toml

        cp $BUILDDIR/unlynx_test_data.txt $srv
        #cp $BUILDDIR/unlynx/pre_compute_multiplications.gob $srv

        runSrv $n &
    done


}

runSrv(){
    cd srv$1
    ../unlynx -d $DBG_SRV server -c private.toml
    cd ..
}

runCl(){
    G=group.toml
    shift
    echo "Running Client with $G $@"
    ./unlynx -d $DBG_CLIENT $@ -f $G -s "{s0, s1}" -w "{w0, 1, w1, 1}" -p "(v0 == v1 && v2 == v3)" -g "{g0, g1, g2}"
}


#------- CLEAR SERVERS --------#
clearSrv(){
    pkill -9 unlynx
}


#------- OTHER STUFF --------#
if [ "$1" == "-q" ]; then
  DBG_RUN=
  STATICDIR=
fi

main
