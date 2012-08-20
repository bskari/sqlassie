/*
 * SQLassie - database firewall
 * Copyright (C) 2011 Brandon Skari <brandon.skari@gmail.com>
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
 * Parses MySQL queries and computes the probability of attack.
 * @author Brandon Skari
 * @date January 3 2011
 */

#include "AttackProbabilities.hpp"
#include "DlibProbabilities.hpp"
#include "Logger.hpp"
#include "nullptr.hpp"
#include "ParserInterface.hpp"
#include "QueryRisk.hpp"
#include "ReadlineStream.hpp"
#include "SensitiveNameChecker.hpp"

#include <boost/math/special_functions/fpclassify.hpp>
#include <cassert>
#include <fstream>
#include <iostream>
#include <string>

using boost::math::isnan;
using std::cerr;
using std::cout;
using std::endl;
using std::ifstream;
using std::istream;
using std::string;

const double CUTOFF = 0.5;
const int NUM_PROBABILITIES = 6;
const int NUM_QUERY_TYPES = 10;

static void setProbabilities(
    const QueryRisk& qr,
    AttackProbabilities* probs,
    double probabilities[]
);


int main(int argc, char* argv[])
{
    Logger::initialize();
    SensitiveNameChecker::initialize();
    SensitiveNameChecker::get().setPasswordSubstring("password");
    SensitiveNameChecker::get().setUserSubstring("user");
    const bool file = (argc > 1);
    istream* stream;

    if (file)
    {
        stream = new ifstream(argv[1]);
        if (!stream->good())
        {
            cerr << "Unable to open file '" << argv[1] << "', aborting" << endl;
            return 0;
        }
    }
    else
    {
        stream = new ReadlineStream("risk> ");
    }

    string query;
    int queryCount = 0;
    int queryTypes[NUM_QUERY_TYPES] = {0};

    DlibProbabilities dp;
    while (!stream->eof() && queryCount < 500)
    {
        getline(*stream, query);

        if (0 == query.length())
        {
            continue;
        }

        QueryRisk qr;
        ParserInterface parser(query);

        const bool successfullyParsed = parser.parse(&qr);
        ++queryCount;

        // If the query was successfully parsed (i.e. was a valid query)
        if (successfullyParsed && qr.valid)
        {
            assert(
                qr.queryType < NUM_QUERY_TYPES
                && "queryTypes array is too small for the number of query "
                && "types in the QueryRisk::QueryType enum"
            );
            ++queryTypes[qr.queryType];

            if (!file)
            {
                cout << qr << endl;
            }

            double dlibProbabilities[NUM_PROBABILITIES];
            const char* const names[NUM_PROBABILITIES] = {
                "Bypass authentication",
                "Data access",
                "Data modification",
                "Fingerprinting",
                "Schema",
                "Denial of service"
            };

            setProbabilities(qr, &dp, dlibProbabilities);

            double* probabilities[1] = {
                dlibProbabilities
            };
            const char* listNames[1] = {
                "Dlib"
            };

            assert(
                sizeof(probabilities) / sizeof(probabilities[0]) ==
                    sizeof(listNames) / sizeof(listNames[0])
                && "List of probabilities and names of the lists should be "
                && "the same size"
            );

            bool queryPrinted = false;
            for (
                size_t listNum = 0;
                listNum < sizeof(probabilities) / sizeof(probabilities[0]);
                ++listNum
            )
            {
                for (int i = 0; i < NUM_PROBABILITIES; ++i)
                {
                    if (!file && probabilities[listNum][i] > 0.0)
                    {
                        cout << names[i]
                            << ": "
                            << probabilities[listNum][i]
                            << endl;
                    }
                    else if (probabilities[listNum][i] > CUTOFF)
                    {
                        if (!queryPrinted)
                        {
                            cout << query << endl;
                            queryPrinted = true;
                        }
                        cout << names[i]
                            << ": "
                            << probabilities[listNum][i]
                            << endl;
                    }
                    // NANs mean something is wrong with the network or with
                    // the Bayesian library
                    else if (isnan(probabilities[listNum][i]))
                    {
                        cerr << "Got a NAN for probability of "
                            << names[i]
                            << "!!!\n"
                            << "This is likely due to an error in either the "
                            << "Bayesian library, or the Bayesian net file."
                            << endl;
                    }
                }
            }
        }
        else
        {
            cerr << "Query #" << queryCount << " did not parse" << endl;
        }
    }

    if (!file)
    {
        cout << endl;
    }
    return 0;
}


void setProbabilities(
    const QueryRisk& qr,
    AttackProbabilities* probs,
    double probabilities[]
)
{
    assert(
        nullptr != probs &&
        "The probability calculator should not be null"
    );
    if (nullptr == probs)
    {
        return;
    }
    // Authentication bypass attack
    if (QueryRisk::TYPE_SELECT == qr.queryType && qr.userTable)
    {
        probabilities[0] = probs->getProbabilityOfBypassAttack(qr);
    }
    else
    {
        probabilities[0] = 0.0;
    }

    // Data access attack
    if (QueryRisk::TYPE_SELECT == qr.queryType)
    {
        probabilities[1] = probs->getProbabilityOfAccessAttack(qr);
    }
    else
    {
        probabilities[1] = 0.0;
    }

    // Data modification attack
    if (
        QueryRisk::TYPE_UPDATE == qr.queryType ||
        QueryRisk::TYPE_INSERT == qr.queryType ||
        QueryRisk::TYPE_DELETE == qr.queryType
    )
    {
        probabilities[2] = probs->getProbabilityOfModificationAttack(qr);
    }
    else
    {
        probabilities[2] = 0.0;
    }

    // Fingerprinting attack
    // Fingerprinting attacks can come from select or data mods!
    if (
        QueryRisk::TYPE_SELECT == qr.queryType
        || QueryRisk::TYPE_INSERT == qr.queryType
        || QueryRisk::TYPE_UPDATE == qr.queryType
        || QueryRisk::TYPE_DELETE == qr.queryType
    )
    {
        probabilities[3] =
            probs->getProbabilityOfFingerprintingAttack(qr);
    }
    else
    {
        probabilities[3] = 0.0;
    }

    // Schema discovery attack
    // Schema attacks can come from select or data mods!
    if (
        QueryRisk::TYPE_SELECT == qr.queryType
        || QueryRisk::TYPE_INSERT == qr.queryType
        || QueryRisk::TYPE_UPDATE == qr.queryType
        || QueryRisk::TYPE_DELETE == qr.queryType
    )
    {
        probabilities[4] = probs->getProbabilityOfSchemaAttack(qr);
    }
    else
    {
        probabilities[4] = 0.0;
    }

    // Denial of service attack
    if (QueryRisk::TYPE_SELECT == qr.queryType)
    {
        probabilities[5] = probs->getProbabilityOfDenialAttack(qr);
    }
    else
    {
        probabilities[5] = 0.0;
    }
}
