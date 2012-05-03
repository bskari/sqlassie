#!/bin/bash
# MySQL stress test.
# Usage: ./mysqlStress.sh [port] [iterations] [user] [database] [query]
set -e
set -u

if [ "$#" -ge 1 ] ;
then
    port="$1"
else
    port=3306
fi

if [ "$#" -ge 2 ] ;
then
    iterations="$2"
else
    iterations=10000
fi

if [ "$#" -ge 3 ] ;
then
    user="$3"
else
    user='sqlassie'
fi

if [ "$#" -ge 4 ] ;
then
    database="$4"
else
    database='mysql'
fi

if [ "$#" -ge 5 ] ;
then
    query="$5"
else
    query="SELECT User, Host, User FROM user ORDER BY User, Host LIMIT 1, 3;"
fi

command="mysql -u $user -P $port $database -h 127.0.0.1"
echo "$command"
yes "$query" | head -n "$iterations" | $command > /dev/null
