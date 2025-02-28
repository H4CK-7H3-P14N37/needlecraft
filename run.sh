#!/bin/bash
if [ ! -d "./reports" ]; then
    mkdir ./reports
fi
docker run -d -it --env-file .env -v ./reports:/data/needlecraft/reports --name needlecraft-$(date -u +"%Y-%m-%d") needlecraft bash

docker exec -it needlecraft-$(date -u +"%Y-%m-%d") bash

