/*
 * SQLassie - database firewall
 * Copyright (C) 2012 Brandon Skari <brandon.skari@gmail.com>
 *
 * This file is part of SQLassie.
 *
 * SQLassie is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * SQLassie is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with SQLassie. If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * Tests the failsafe-ness of the parser by constructing random queries and
 * trying to parse them. Queries that crash the parser are printed.
 * @author Brandon Skari
 * @date August 28 2012
 */

// This needs to be defined prior to including the scanner header
#define YY_DECL int sql_lex( \
    ScannerContext* const context, \
    yyscan_t yyscanner \
)

#include "../Logger.hpp"
#include "../nullptr.hpp"
#include "../ParserInterface.hpp"
#include "../QueryRisk.hpp"
#include "../scanner.yy.hpp"
#include "../ScannerContext.hpp"
#include "../SensitiveNameChecker.hpp"
#include "../sqlParser.h"

#include <cassert>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/timeb.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <utility>
#include <vector>

using std::cerr;
using std::cout;
using std::endl;
using std::ifstream;
using std::map;
using std::ostringstream;
using std::pair;
using std::string;
using std::vector;

// Methods from the scanner
extern YY_DECL;

/**
 * Loads a file full of legitimate queries (one per line) and prepares the
 * Markov chain map for use with generateRandomQuery.
 */
static void initializeRandomQueries(const char* filename);
/**
 * Generates a (possibly invalid) random query. Queries will be generated
 * using the Markov chain map.
 */
static string generateRandomQuery(unsigned int* randState);

static unsigned int getRandSeed();

typedef int token_t;
typedef float probability_t;
// Mapping from a token to tokens that followed it in the sample file, along
// with a CPD of that token or one of the previous tokens being used.
// For example:
// SELECT => {
//   (STAR, .3),
//   (INTEGER, .4),
//   (STRING, .5),
//   (IDENTIFIER, 1.0)
// },
// ...
static map<token_t, vector<pair<token_t, probability_t> > > tokenToTokenCpd;
static map<token_t, string> tokenToString;

static const int IPC_SIZE = 4096;


int main(int argc, char* argv[])
{
    Logger::initialize();
    SensitiveNameChecker::initialize();
    SensitiveNameChecker::setUserSubstring("user");
    SensitiveNameChecker::setPasswordSubstring("password");

    if (argc > 1)
    {
        initializeRandomQueries(argv[1]);
    }
    else
    {
        initializeRandomQueries("../src/tests/queries/wikidb.sql");
    }

    unsigned int randState = getRandSeed();

    const key_t key = rand_r(&randState);
    const int shmid = shmget(key, IPC_SIZE, IPC_CREAT | 0666);
    if (shmid < 0)
    {
        cerr << "Unable to create shared memory" << endl;
        exit(EXIT_FAILURE);
    }
    char* const sharedMemory = static_cast<char*>(shmat(shmid, nullptr, 0));
    if (reinterpret_cast<char*>(-1) == sharedMemory)
    {
        cerr << "Unable to access shared memory" << endl;
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < 100; ++i)
    {
        // Run the parser in another process so that we can monitor crashes
        const pid_t pid = fork();

        // Child process
        if (0 == pid)
        {
            // The child needs to reseed so that it doesn't get the same query
            // every time
            randState = getRandSeed();

            QueryRisk qr;
            while (true)
            {
                const string query(generateRandomQuery(&randState));

                // Use strncat instead of strncpy to avoid overhead of padding
                // the rest of the string with '\0's
                sharedMemory[0] = '\0';
                strncat(sharedMemory, query.c_str(), query.size());
                sharedMemory[IPC_SIZE - 1] = '\0';

                ParserInterface parser(query);
                const bool _ = parser.parse(&qr);
                if (_) {}  // Silence compiler warning
            }
        }
        // Parent
        else
        {
            int status;
            waitpid(pid, &status, 0);
            cout << "Child terminated, last query was:\n";
            cout << sharedMemory << endl;
        }
    }

    exit(EXIT_SUCCESS);
}


void initializeRandomQueries(const char* filename)
{
    ifstream fin(filename);
    if (!fin)
    {
        cerr << "Unable to open file " << filename << endl;
        exit(EXIT_FAILURE);
    }

    string s;
    // All the size_t counts will be initialized to 0 upon creation
    map<token_t, map<token_t, size_t> > tokenToTokenCount;

    while (getline(fin, s))
    {
        yyscan_t scanner;
        if (0 != sql_lex_init(&scanner))
        {
            cerr << "Unable to initialize scanner for"
                " initializeRandomQueries" << endl;
            exit(EXIT_FAILURE);
        }
        YY_BUFFER_STATE bufferState = sql__scan_string(s.c_str(), scanner);
        if (nullptr == bufferState)
        {
            cerr << "Unable to initialize scanner buffer for"
                " initializeRandomQueries" << endl;
            exit(EXIT_FAILURE);
        }

        QueryRisk qr;
        ScannerContext sc(&qr);
        const int endOfTokensLexCode = 0;
        int lexCode = sql_lex(&sc, scanner);
        int previousLexCode = -1;
        // We want to go up to and include the end token - that way we can
        // keep track of which tokens ended a query
        while (endOfTokensLexCode != previousLexCode)
        {
            // Insert the token's string value if it hasn't been saved yet
            if (tokenToString.end() == tokenToString.find(lexCode))
            {
                if (STRING == lexCode)
                {
                    tokenToString[lexCode] = "\"" + sc.quotedString + "\"";
                }
                else
                {
                    tokenToString[lexCode] = sql_get_text(scanner);
                }
            }

            // Insert and count the tokens that followed this one
            if (-1 != previousLexCode)
            {
                ++tokenToTokenCount[previousLexCode][lexCode];
            }

            previousLexCode = lexCode;
            lexCode = sql_lex(&sc, scanner);
        }

        sql__delete_buffer(bufferState, scanner);
        sql_lex_destroy(scanner);
    }

    // Compute and store the cpd
    map<token_t, map<token_t, size_t> >::const_iterator end(
        tokenToTokenCount.end()
    );
    for (
        map<token_t, map<token_t, size_t> >::const_iterator i(
            tokenToTokenCount.begin()
        );
        i != end;
        ++i
    )
    {
        // Get the total number of tokens that followed this one
        size_t numTokensFollowing = 0;
        map<token_t, size_t>::const_iterator end2(i->second.end());
        for (
            map<token_t, size_t>::const_iterator j(i->second.begin());
            j != end2;
            ++j
        )
        {
            numTokensFollowing += j->second;
        }

        // Now fill in the cpd
        probability_t cumulativeProbability = 0.0;
        for (
            map<token_t, size_t>::const_iterator j(i->second.begin());
            j != end2;
            ++j
        )
        {
            const probability_t tokenProbability =
                static_cast<probability_t>(j->second) / numTokensFollowing;
            tokenToTokenCpd[i->first].push_back(
                pair<token_t, probability_t>(
                    j->first,
                    tokenProbability + cumulativeProbability
                )
            );
            cumulativeProbability += tokenProbability;
        }
    }
}


string generateRandomQuery(unsigned int* randState)
{
    ostringstream out;
    // All queries begin with SELECT, INSERT, UPDATE, DELETE, SET, SHOW,
    // DESCRIBE, or EXPLAIN.
    const token_t beginTokens[] = {
        SELECT, INSERT, UPDATE, DELETE, SET, SHOW, DESCRIBE, EXPLAIN
    };
    token_t token = beginTokens[
        rand_r(randState) % (sizeof(beginTokens) / sizeof(beginTokens[0]))
    ];
    const size_t maxToken = tokenToString.rbegin()->first;

    // Always make sure that we start on a token that's used in the input file
    do
    {
        // @TODO ideally this should exactly pick from the values in
        // tokenToString
        token = rand_r(randState) % (maxToken + 1);
    }
    while (tokenToString.end() == tokenToString.find(token));

    // While not end of query
    while (0 != token)
    {
        out << tokenToString.at(token) << ' ';

        // Some of the time, we'll just choose a random token
        const bool chooseRandomToken =
            (static_cast<probability_t>(rand_r(randState)) / RAND_MAX) < 0.05;

        if (chooseRandomToken)
        {
            // Always make sure that we choose a token that's used in the
            // input query file
            do
            {
                // @TODO ideally this should exactly pick from the values in
                // tokenToString
                token = rand_r(randState) % (maxToken + 1);
            }
            while (tokenToString.end() == tokenToString.find(token));
        }
        else
        {
            if (tokenToTokenCpd.end() == tokenToTokenCpd.find(token))
            {
                cout << "FUCK" << endl;
                cout << token << " " << tokenToString.at(token) << endl;
                cout << "what" << endl;
            }
            // Use the Markov chain to choose a value
            const probability_t tokenProbability =
                static_cast<probability_t>(rand_r(randState)) / RAND_MAX;
            vector<pair<token_t, probability_t> >::const_iterator end(
                tokenToTokenCpd.at(token).end()
            );
            for (
                vector<pair<token_t, probability_t> >::const_iterator i(
                    tokenToTokenCpd.at(token).begin()
                );
                i != end;
                ++i
            )
            {
                if (i->second >= tokenProbability)
                {
                    token = i->first;
                    break;
                }
            }
        }

        // Something should have been chosen by now, so if we get here,
        // something went wrong. If we haven't hit the end of the query yet,
        // and there's a mapping for the token, then just grab the last one.
        // Otherwise, just generate another token.
        if (0 != token && tokenToTokenCpd.end() == tokenToTokenCpd.find(token))
        {
            token = tokenToTokenCpd.at(token).back().first;
        }
    }

    return out.str();
}


static unsigned int getRandSeed()
{
    timeb timeStruct;
    ftime(&timeStruct);
    return (timeStruct.time / 1000) * 1000 + timeStruct.millitm;
}
