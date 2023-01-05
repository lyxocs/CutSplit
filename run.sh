#!/bin/bash

if [ -e result.csv ]
then
    rm result.csv
fi

make clean
make
if [ ! -e $1 ]
then
    echo 'rule File not exists '$1
    exit 1
fi

if [ ! -e $2 ]
then
    echo 'trace File not exists '$2
    exit 1
fi

sip=0
dip=0

for sip in $(seq 0 32)
do
    for dip in $(seq 0 32)
    do
        cmd='./main -r '$1' -e '$2' -s '$sip' -d '$dip
        echo $cmd
        eval $cmd
    done
done
