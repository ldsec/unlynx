#!/usr/bin/env bash

SSH_TYPE="-t ssh-ed25519"
SERVERS="$@"

compileLinux.sh

for s in $SERVERS; do
    login=root@iccluster0$s.iccluster.epfl.ch

    scp medco $login:
    scp medco_test_data.txt $login:
    scp pre_compute_multiplications.gob $login:
done

rm -rf medco
compileMac.sh

