#! /bin/bash

echo "Syncing..."
rsync -vve 'ssh -p 1722' module/lisakmod.ko testmod.sh ../target/release/kmodtest localhost:/tmp/

echo "Running..."
ssh localhost -p 1722 bash /tmp/testmod.sh
