#!/bin/bash

docker build . -t ezviz_builder
docker run -v $(pwd):/root/output -it ezviz_builder