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

#include "AttackProbabilities.hpp"
#include "DlibProbabilities.hpp"
#include "Logger.hpp"
#include "MySqlGuard.hpp"
#include "nullptr.hpp"
#include "ParserInterface.hpp"
#include "QueryRisk.hpp"
#include "SensitiveNameChecker.hpp"

#include <algorithm>
#include <cassert>
#include <fstream>
#include <iostream>
#include <string>

using std::cout;
using std::distance;
using std::find;
using std::ifstream;
using std::max_element;
using std::string;

/**
 * Demo backend for the site. Parses MySQL queries provided as the first
 * argument and computes how SQLassie would respond.
 * @author Brandon Skari
 * @date December 3 2011
 */

const int NUM_PROBABILITIES = 6;
const int NUM_QUERY_TYPES = 10;

enum RESPONSE_TYPES
{
    FAKE_EMPTY_SET = 0,
    FAKE_OK = 1,
    FAKE_ERROR = 2
};

enum ATTACK_TYPES
{
    NO_ATTACK = 0,
    AUTHENTICATION_BYPASS = 1,
    DATA_ACCESS = 2,
    DATA_MODIFICATION = 3,
    FINGERPRINTING = 4,
    SCHEMA = 5,
    DENIAL_OF_SERVICE = 6
};

const int FAILED_TO_PARSE = 100;

void setProbabilities(
    QueryRisk& qr,
    AttackProbabilities* probs,
    double probabilities[]
)
{
    assert(nullptr != probs &&
        "The probability calculator should not be null");
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
    if (QueryRisk::TYPE_UPDATE == qr.queryType ||
        QueryRisk::TYPE_INSERT == qr.queryType ||
        QueryRisk::TYPE_DELETE == qr.queryType)
    {
        probabilities[2] = probs->getProbabilityOfModificationAttack(qr);
    }
    else
    {
        probabilities[2] = 0.0;
    }

    // Fingerprinting attack
    // Fingerprinting attacks can come from select or data mods!
    if (QueryRisk::TYPE_SELECT == qr.queryType
        || QueryRisk::TYPE_INSERT == qr.queryType
        || QueryRisk::TYPE_UPDATE == qr.queryType
        || QueryRisk::TYPE_DELETE == qr.queryType)
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
    if (QueryRisk::TYPE_SELECT == qr.queryType
        || QueryRisk::TYPE_INSERT == qr.queryType
        || QueryRisk::TYPE_UPDATE == qr.queryType
        || QueryRisk::TYPE_DELETE == qr.queryType)
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


int main(int argc, char* argv[])
{
    Logger::initialize();
    SensitiveNameChecker::initialize();
    SensitiveNameChecker::get().setPasswordSubstring("password");
    SensitiveNameChecker::get().setUserSubstring("user");
    if (argc < 2)
    {
        // If no input is provided, print an error
        cout << FAILED_TO_PARSE << ' ' << FAKE_ERROR;
        exit(0);
    }

    DlibProbabilities dp;
    string query(argv[1]);

    if (0 == query.length())
    {
        cout << FAILED_TO_PARSE << ' ' << FAKE_ERROR;
        exit(0);
    }

    QueryRisk qr;
    ParserInterface parser(query);

    const int status = parser.parse(&qr);

    // If the query was successfully parsed (i.e. was a valid query)
    if (0 == status && qr.valid)
    {
        assert(
            qr.queryType < NUM_QUERY_TYPES
            && "queryTypes array is too small for the number of query types "
            && "in the QueryRisk::QueryType enum"
        );

        double probabilities[NUM_PROBABILITIES];

        setProbabilities(qr, &dp, probabilities);

        const double maxProb = *max_element(
            probabilities,
            probabilities + NUM_PROBABILITIES
        );
        // I know this is slow, but I'm lazy
        const ATTACK_TYPES attackType = static_cast<ATTACK_TYPES>(
            1 +
            distance(
                probabilities,
                find(
                    probabilities,
                    probabilities + NUM_PROBABILITIES,
                    maxProb
                )
            )
        );

        if (maxProb < PROBABILITY_BLOCK_LEVEL)
        {
            cout << NO_ATTACK << ' ' << 0;
        }
        else
        {
            // Print SQLassie's response
            int sqlassieResponse = FAKE_EMPTY_SET;
            switch (qr.queryType)
            {
                case QueryRisk::TYPE_UNKNOWN:
                    Logger::log(Logger::ERROR)
                        << "Unknown query types should not be parsed";
                    assert(false);
                    sqlassieResponse = FAKE_EMPTY_SET;
                    break;
                case QueryRisk::TYPE_SELECT:
                case QueryRisk::TYPE_SHOW:
                    sqlassieResponse = FAKE_EMPTY_SET;
                    break;
                case QueryRisk::TYPE_INSERT:
                case QueryRisk::TYPE_UPDATE:
                case QueryRisk::TYPE_DELETE:
                    sqlassieResponse = FAKE_OK;
                    break;
                case QueryRisk::TYPE_TRANSACTION:
                case QueryRisk::TYPE_SET:
                case QueryRisk::TYPE_EXPLAIN:
                case QueryRisk::TYPE_DESCRIBE:
                    Logger::log(Logger::ERROR)
                        << "Non-risky query type was mistakenly blocked";
                    assert(false);
                    sqlassieResponse = FAKE_EMPTY_SET;
                    break;
                default:
                    Logger::log(Logger::ERROR)
                        << "Unexpected attack type in switch "
                        << qr.queryType;
                    assert(false);
                    sqlassieResponse = FAKE_EMPTY_SET;
            }
            cout << attackType << ' ' << sqlassieResponse;
        }
    }
    else
    {
        cout << FAILED_TO_PARSE << ' ' << FAKE_ERROR;
    }

    return 0;
}
