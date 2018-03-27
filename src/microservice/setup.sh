#!/usr/bin/env bash
#set -e

function help() {
    printf "Usage:\nsetup.sh <db-password>\n"
    exit 1
}

if [ -z "$1" ]; then help; fi

sudo -i -u postgres psql -c "create database auth_microservice;"
sudo -i -u postgres psql -c "create user auth_microservice with encrypted password '${1}';"
sudo -i -u postgres psql -c "grant all privileges on database auth_microservice to auth_microservice;"

