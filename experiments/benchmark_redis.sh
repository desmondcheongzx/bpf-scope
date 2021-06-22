#!/bin/bash

runs=50
total=0
for (( i = 0; i < runs; i++))
do
        redis-cli flushall
        result=$(redis-benchmark -t $1 -n 100000 -q --csv
		    | sed 's/"//g'
		    | sed 's/,/ /g'
		    | awk '{print $2}')
        total=$(echo "$total + $result" | bc)
        echo $result
done
echo Average $(echo "$total / $runs" | bc) requests/s over $runs runs
