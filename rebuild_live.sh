#!/bin/bash

read -p "./live directory contents are about to be destroyed, continue? y/N" -n 1 -r
echo # move to new line

if [[ ! $REPLY =~ ^[Yy]$ ]]
then
	echo "Operation aborted."
	exit 1
fi

echo "PROCEEDING! ...."
rm -rf ./live
mkdir -p ./live

# need libkyu.wasm, libkyu.js (WASM glue), kyu.js, demo.js, and index.html
cp -v ./libkyu.wasm live/
cp -v ./libkyu.js live/
cp -v ./kyu.js live/
cp -v ./demo.js live/
cp -v ./demo.html live/index.html
cp -v ./serve.sh live/serve.sh


if [ "$1" == "go" ]; then
	cd ./live
	echo "Starting Live Server..."
	python -m http.server 8080
else
	echo "./live has been rebuilt. Exiting! :3"
fi

