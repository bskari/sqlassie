#!/bin/bash
# Multi-threaded MySQL stress test.
# Usage: ./mysqlMultiThreadedStress.sh [threads] [port] [iterations] [user] [database] [query]
set -e
set -u

if [ "$#" -lt 1 ];
then
    echo "Usage: $0 <threads> [port] [iterations] [user] [database] [query]" 1>&2
    exit 0
fi

set +u
echo ./mysqlStress.sh "$2" "$3" "$4" "$5" "$6" ;
set -u

for i in $(seq 1 "$1")
do
    coproc_name=coproc_$i
    set +u
        coproc "$coproc_name" { ./mysqlStress.sh $2 $3 $4 $5 $6 ; }
    set -u
    pid_arr["$i"]="$!"
done

for i in $(seq 1 "$1")
do
    wait ${pid_arr["$i"]}
done
