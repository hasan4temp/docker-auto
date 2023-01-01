#!/bin/bash

dockerfullid_mariadb=$(docker container ls --all --quiet --no-trunc --filter "name=mariadb")

mkdir -p /docker-logs
chmod 777 /docker-logs
publicIP=$(wget -qO - icanhazip.com)

file_name=$(date +%Y-%m-%d-%H-%M-%S)

log=$(docker container logs --since=6h $dockerfullid_mariadb)
echo $log > /docker-logs/$file_name

curl -F log_file=@/var/lib/docker/containers/$dockerfullid_mariadb/$dockerfullid_mariadb-json.log http://cluster.aamarpay.com/cluster-server/api/post-logs/$publicIP