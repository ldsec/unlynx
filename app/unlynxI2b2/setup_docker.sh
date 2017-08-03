#!/usr/bin/env bash

SSH_TYPE="-t ssh-ed25519"
SERVERS="$@"

for s in $SERVERS; do
    echo "Setting up iccluster0$s.iccluster.epfl.ch..."
    login=root@iccluster0$s.iccluster.epfl.ch
    cat install_script.sh | ssh $login /bin/bash
done
