#!/usr/bin/env bash

apt-get update

yes Y | apt-get install git

apt-get install \
    apt-transport-https \
    ca-certificates \
    curl \
    software-properties-common \
    screen

curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -

apt-key fingerprint 0EBFCD88

add-apt-repository \
   "deb [arch=amd64] https://download.docker.com/linux/ubuntu \
   $(lsb_release -cs) \
   stable"

apt-get update

yes Y | apt-get install docker-ce

docker run hello-world

curl -L https://github.com/docker/compose/releases/download/1.14.0/docker-compose-`uname -s`-`uname -m` > /usr/local/bin/docker-compose

chmod +x /usr/local/bin/docker-compose

sudo add-apt-repository "deb http://apt.postgresql.org/pub/repos/apt/ trusty-pgdg main"

wget --quiet -O - https://www.postgresql.org/media/keys/ACCC4CF8.asc | sudo apt-key add -

sudo apt-get update

sudo apt-get install postgresql-client-9.6

#git clone https://c4science.ch/source/medco-deployment.git
 