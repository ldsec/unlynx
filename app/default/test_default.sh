#!/usr/bin/env bash

DBG_SHOW=1
# Debug-level for server
DBG_SRV=1
# Debug-level for client
DBG_CLIENT=1
# For easier debugging
BUILDDIR=$(pwd)
STATICDIR=test

. lib/test/libtest.sh

main(){
    startTest
    build
    test Build
    test ServerCfg
    test RunMedco
    clearSrv
    stopTest
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
        go build -o medco -a $BUILDDIR/medco/*go
    fi

    for n in $(seq $NBR); do
        srv=srv$n
        rm -rf $srv
        mkdir $srv
        cp $BUILDDIR/medco/medco_test_data.txt $srv
        cp $BUILDDIR/medco/pre_compute_multiplications.gob $srv
    done
}


#------- SERVER CONFIGURATION --------#
testServerCfg(){
    for n in $(seq $NBR); do
        runSrvCfg $n
        pkill medco
        testFile srv$n/config.toml
    done
}

runSrvCfg(){
    echo -e "127.0.0.1:200$1\n$(pwd)/srv$1\n" | ./medco server setup > $OUT
}


#------- CLIENT CONFIGURATION --------#
testRunMedco(){
    setupServers
    echo "Running Medco APP"
    runCl 1 run
}

setupServers(){
    rm -f group.toml
    for n in $(seq $NBR); do
        srv=srv$n
        rm -f $srv/*
        runSrvCfg $n
        tail -n 4 $srv/group.toml >> group.toml

        cp $BUILDDIR/medco/medco_test_data.txt $srv
        cp $BUILDDIR/medco/pre_compute_multiplications.gob $srv

        runSrv $n &
    done


}

runSrv(){
    cd srv$1
    ../medco -d $DBG_SRV server -c config.toml
    cd ..
}

runCl(){
    G=group.toml
    shift
    echo "Running Client with $G $@"
    ./medco -d $DBG_CLIENT $@ -g $G
}


#------- CLEAR SERVERS --------#
clearSrv(){
    #rm -rf $BUILDDIR/$STATICDIR
    pkill medco
}


#------- OTHER STUFF --------#
if [ "$1" == "-q" ]; then
  DBG_RUN=
  STATICDIR=
fi

main