#! /bin/bash

cargo build --release -p kmodtest
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

cd $DIR/module && (make || (cd $DIR && false)) && \
cd $DIR && \
./test_remote.sh