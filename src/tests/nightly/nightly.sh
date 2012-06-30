#!/bin/bash
# SQLassie nightly regression script.
# Times how long it takes to build debug and release versions, times and runs
# the test suite, runs a stress test against a web app, and runs a stress test
# directly against the database.
set -u
set -e

# Globals used in saveMessage
baseDir=''
outputFile=''

function saveMessage()
{
    if [ $# -ne 1 ];
    then
        echo 'saveMessage called without message'
        return
    fi

    echo $(date +'%Y-%m-%d %H:%M ') $1 | tee -a "$baseDir/$outputFile"
}

function update()
{
    git fetch origin > /dev/null
    git pull origin HEAD > /dev/null
}

function runMake()
{
    pushd src

        if [ $# -ne 1 ];
        then
            echo 'runMake requires build type argument'
            return
        fi
        local version="$1"

        local tempFilename=$(mktemp)
        set -o pipefail
            /usr/bin/time -f '%U' make VERSION=$version 2>&1 | tee $tempFilename
        set +o pipefail
        local makeExitStatus=$?
        local time_=$(tail -n 1 $tempFilename)
        rm $tempFilename

        if [ "$?" -ne $makeExitStatus ];
        then
            saveMessage 'Failed to build'
            exit 0
        fi

        saveMessage "Built in $time_"

    popd
}

function runTest()
{
    pushd bin

        echo 'Running test'
        set +e
            local errorCount=$(./test 2>&1 | tail -n 1 | grep '***' | awk '{print $2}')
        set -e

        if [ -z "$errorCount" ];
        then
            saveMessage 'Test probably failed'
        elif [ "$errorCount" -eq 0 ];
        then
            saveMessage 'No test failures; test probably broke'
        else
            saveMessage "$errorCount errors in test"
        fi

    popd
}

function runTestTime()
{
    pushd bin
        set +e
            # Run the test once to warm up the cache
            ./test --run-test=testParseKnownGoodQueries

            local time_=$(/usr/bin/time -f '%U' ./test --run_test=testParseKnownGoodQueries --result-code=no 2>&1 | tail -n 1)
        set -e

        saveMessage "Test ran in $time_ seconds"

    popd
}

function runCrawler()
{
    # Run SQLassie
    pushd bin
        set +e
            killall -s 2 sqlassie 2> /dev/null
        set -e
        sleep 2
        ./sqlassie -l 3307 -s /run/mysqld/mysqld.sock &
        local sqlassiePid=$!
    popd

    # Give it a second to start up
    sleep 1

    echo 'runCrawler'
    pushd src/tests/nightly
        set +e
            local time_=$(/usr/bin/time -f '%e' python crawl_ccdc.py 2>&1 | tail -n 1)
            if [ "$?" -ne 0 ];
            then
                saveMessage 'Failed to run crawler'
                exit 0
            fi
        set -e
    popd

    saveMessage "Crawler ran in $time_ seconds"

    # Kill SQLassie
    set +e
        killall -s 2 sqlassie 2> /dev/null
        sleep 2
        killall -s 9 $sqlassiePid 2> /dev/null
    set -e
}

function runStress ()
{
    echo 'Running stress'

    # Run SQLassie
    pushd bin
        set +e
            killall -s 2 sqlassie 2> /dev/null
        set -e
        sleep 2
        ./sqlassie -l 3307 -s /run/mysqld/mysqld.sock &
        local sqlassiePid=$!
    popd

    # Give it a second to start up
    sleep 1

    for port in 3306 3307 ;
    do
        echo "$port"
        set +e
            local time_=$(/usr/bin/time -f '%E' bash src/tests/nightly/mysqlStress.sh $port 2>&1 | tail -n 1)
            if [ "$?" -ne 0 ];
            then
                saveMessage 'Failed to run stress'
                exit 0
            fi
        set -e
        saveMessage "Stress:$port took $time_"
    done

    # Kill SQLassie
    set +e
        killall -s 2 sqlassie 2> /dev/null
        sleep 2
        killall -s 9 $sqlassiePid 2> /dev/null
    set -e
}

function runStaticAnalysis ()
{
    # I'm choosing not to follow these guidelines from Google
    local filters='-whitespace/braces'
    filters="$filters,-whitespace/parens"
    filters+="$filters,-runtime/rtti"
    # I haven't gotten around to following these guidelines yet
    filters="$filters,-whitespace/tabs"

    for staticAnalysisTool in \
        'cppcheck --error-exitcode=1 --max-configs=50' \
        "cpplint.py --filter=$filters"
    do
        if [ ! -z "$(which $staticAnalysisTool)" ];
        then
            pushd src
                for sourceFile in *cpp *hpp;
                do
                    set +e
                        $staticAnalysisTool $sourceFile
                        local exitCode=$?
                    set -e
                    if [ $exitCode -ne 0 ];
                    then
                        saveMessage "$sourceFile failed $staticAnalysisTool"
                    fi
                done
            popd
        fi
    done
}

function getLoad ()
{
    local rawLoad=$(uptime | awk '{print $10}' | sed 's/,//')
    # Convert load to an integer percentage
    local bcCommand="scale=0; ($rawLoad * 100) / 1"
    echo "$bcCommand" | bc
}

function waitForLowLoad ()
{
    local waitCount=0
    local load=$(getLoad)
    while [ "$load" -gt 5 ] ;
    do
        echo 'Load is '"$load"'%, waiting...'
        local waitCount=$((waitCount + 1))
        if [ "$waitCount" -gt 60 ] ;
        then
            echo "Giving up"
            exit 0
        fi
        sleep 60
        load=$(getLoad)
    done
    echo 'Load is ' "$load"'%, running!'
}

waitForLowLoad

baseDir=$(cd ../../.. > /dev/null; pwd) # Into main SQLassie directory
cd "$baseDir"
update

pushd src
    # Either Makefile will work for `make clean`
    rm -f Makefile
    ln -s Makefile.gcc Makefile
    make clean
popd

runStaticAnalysis

for version in RELEASE DEBUG ;
do
    for compiler in gcc ;
    do
        outputFile="$version-$compiler.txt"
        echo 'outputfile = '"$outputFile"
        pushd src
            rm -f Makefile
            ln -s Makefile.$compiler Makefile
            make clean
        popd

        runMake "$version"
        runTest
        runTestTime
        runCrawler
        runStress
    done
done
