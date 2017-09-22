#!/usr/bin/env bash

apt-get -y update
apt-get -y install git apt-transport-https ca-certificates curl software-properties-common screen

curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -

apt-key fingerprint 0EBFCD88
wget --quiet -O - https://www.postgresql.org/media/keys/ACCC4CF8.asc | sudo apt-key add -

add-apt-repository \
   "deb [arch=amd64] https://download.docker.com/linux/ubuntu \
   $(lsb_release -cs) \
   stable"
add-apt-repository "deb http://apt.postgresql.org/pub/repos/apt/ trusty-pgdg main"

apt-get -y update
apt-get -y install docker-ce postgresql-client-9.6

docker run hello-world

curl -L https://github.com/docker/compose/releases/download/1.14.0/docker-compose-`uname -s`-`uname -m` > /usr/local/bin/docker-compose

chmod +x /usr/local/bin/docker-compose

#git clone https://c4science.ch/source/medco-deployment.git
