#!/bin/bash
# SQLassie nightly regression script.
# Times how long it takes to build debug and release versions, times and runs
# the test suite, runs a stress test against a web app, and runs a stress test
# directly against the database.
set -u
set -e

function saveMessage()
{
    if [ $# -ne 2 ];
    then
        echo 'saveMessage called without errorCount or file'
        return
    fi

    echo $(date +'%Y-%m-%d %H:%M ') $1 | tee -a $2
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
        version="$1"

        tempFilename=$(mktemp)
        set -o pipefail
            /usr/bin/time -f '%U' make VERSION=$version 2>&1 | tee $tempFilename
        set +o pipefail
        makeExitStatus=$?
        time_=$(tail -n 1 $tempFilename)
        rm $tempFilename

        if [ "$?" -ne $makeExitStatus ];
        then
            saveMessage 'Failed to build' "../$version.txt"
            exit 0
        fi

        saveMessage "Built in $time_" "../$version.txt"

    popd
}

function runTest()
{
    pushd bin

        if [ $# -ne 1 ];
        then
            echo 'runTest requires build type argument'
            return
        fi
        version="$1"

        echo 'Running test for ' "$version"
        set +e
            errorCount=$(./test 2>&1 | tail -n 1 | grep '***' | awk '{print $2}')
        set -e

        if [ -z "$errorCount" ];
        then
            saveMessage 'Test probably failed' "../$version.txt"
        elif [ "$errorCount" -eq 0 ];
        then
            saveMessage 'No test failures; test probably broke' "../$version.txt"
        else
            saveMessage "$errorCount errors in test" "../$version.txt"
        fi

    popd
}

function runTestTime()
{
    pushd bin

        if [ $# -ne 1 ];
        then
            echo 'runTestTime requires build type argument'
            return
        fi
        version="$1"

        set +e
            # Run the test once to warm up the cache
            ./test --run-test=testParseKnownGoodQueries

            time_=$(/usr/bin/time -f '%U' ./test --run_test=testParseKnownGoodQueries --result-code=no 2>&1 | tail -n 1)
        set -e

        saveMessage "Test ran in $time_ seconds" "../$version.txt"

    popd
}

function runCrawler()
{
    if [ $# -ne 1 ];
    then
        echo 'runCrawler requires build type argument'
        return
    fi

    version="$1"
    # Run SQLassie
    pushd bin
        set +e
            killall -s 2 sqlassie 2> /dev/null
        set -e
        sleep 2
        ./sqlassie -l 3307 -s /var/run/mysqld/mysqld.sock &
        sqlassiePid=$!
    popd

    # Give it a second to start up
    sleep 1

    echo 'runCrawler'
    pushd src/tests/nightly
        set +e
            time_=$(/usr/bin/time -f '%e' python crawl_ccdc.py 2>&1 | tail -n 1)
            if [ "$?" -ne 0 ];
            then
                saveMessage 'Failed to run crawler' "sqlassie/$version.txt"
                exit 0
            fi
        set -e
    popd

    saveMessage "Crawler ran in $time_ seconds" "$version.txt"

    # Kill SQLassie
    set +e
        killall -s 2 sqlassie 2> /dev/null
        sleep 2
        killall -s 9 $sqlassiePid 2> /dev/null
    set -e
}

function runStress ()
{
    if [ $# -ne 1 ];
    then
        echo 'runStress requires build type argument'
        return
    fi

    echo 'Running stress'

    version="$1"
    # Run SQLassie
    pushd bin
        set +e
            killall -s 2 sqlassie 2> /dev/null
        set -e
        sleep 2
        ./sqlassie -l 3307 -s /var/run/mysqld/mysqld.sock &
        sqlassiePid=$!
    popd

    # Give it a second to start up
    sleep 1

    for port in 3306 3307 ;
    do
        echo "$port"
        set +e
            time_=$(/usr/bin/time -f '%E' bash src/tests/nightly/mysqlStress.sh $port 2>&1 | tail -n 1)
            if [ "$?" -ne 0 ];
            then
                saveMessage 'Failed to run stress' "sqlassie/$version.txt"
                exit 0
            fi
        set -e
        saveMessage "Stress:$port took $time_" "$version.txt"
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
    filters='-whitespace/braces'
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
                        exitCode=$?
                    set -e
                    if [ $exitCode -ne 0 ];
                    then
                        saveMessage "$sourceFile failed $staticAnalysisTool" '../STATIC.txt'
                    fi
                done
            popd
        fi
    done
}

function waitForLowLoad ()
{
    waitCount=0
    rawLoad=$(uptime | awk '{print $10}' | sed 's/,//')
    # Convert load to an integer percentage
    bcCommand="scale=0; ($rawLoad * 100) / 1"
    load=$(echo "$bcCommand" | bc)
    while [ "$load" -gt 5 ] ;
    do
        echo 'Load is '"$load"'%, waiting...'
        waitCount=$((waitCount + 1))
        if [ "$waitCount" -gt 60 ] ;
        then
            echo "Giving up"
            exit 0
        fi
        sleep 60
        load=$(uptime | awk '{print $10}' | sed 's/,//')
    done
    echo 'Load is ' "$load" '%, running!'
}

waitForLowLoad

cd ../../.. # Into main SQLassie directory
update

pushd src
    make clean
popd

runStaticAnalysis

for version in RELEASE DEBUG ;
do
    pushd src
        make clean
    popd

    runMake "$version"
    runTest "$version"
    runTestTime "$version"
    runCrawler "$version"
    runStress "$version"
done
