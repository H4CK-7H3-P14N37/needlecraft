#!/bin/bash
docker ps -a | grep needlecraft|awk '{print $1}' | xargs docker stop $i
docker ps -a | grep needlecraft|awk '{print $1}' | xargs docker rm $i