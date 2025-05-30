#!/bin/bash
if [ ! -d "./reports" ]; then
    mkdir ./reports
fi
docker-compose up -d --build