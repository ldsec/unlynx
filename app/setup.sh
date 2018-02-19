#!/usr/bin/env bash

SSH_TYPE="-t ssh-ed25519"
SERVERS="$@"

compileLinux.sh

for s in $SERVERS; do
    login=root@iccluster0$s.iccluster.epfl.ch

    scp unlynx $login:
    scp unlynx_test_data.txt $login:
    #scp pre_compute_multiplications.gob $login:
done

rm -rf unlynx

compileMac.sh
