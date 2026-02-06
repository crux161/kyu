#!/bin/bash

read -p "./live directory contents are about to be destroyed, continue? y/N " -n 1 -r
echo # move to new line

if [[ ! $REPLY =~ ^[Yy]$ ]]
then
	echo "Operation aborted."
	exit 1
fi

echo "PROCEEDING! ...."
rm -rf ./live
mkdir -p ./live/img

unzip resources/favicon.zip -d live/img

# 1. Build Artifacts (From Root)
cp -v ./libkyu.wasm live/
cp -v ./libkyu.js live/

# 2. Source Assets (From src/)
# Note: tsc compiles kyu.ts -> kyu.js next to the source file by default
cp -v ./src/kyu.js live/
cp -v ./src/demo.js live/
cp -v ./src/demo.html live/index.html

# 3. Helper Scripts
if [ -f "./scripts/serve.sh" ]; then
    cp -v ./scripts/serve.sh live/
fi

if [ "$1" == "go" ]; then
	cd ./live
	echo "Starting Live Server..."
	python3 -m http.server 8080
else
	echo "./live has been rebuilt. Run 'python3 -m http.server 8080' inside ./live to test."
fi
