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

#include "Logger.hpp"
#include "QueryRisk.hpp"

#include <string>
#include <map>
#include <boost/regex.hpp>
#include <boost/functional/hash/hash.hpp>

using std::endl;
using std::string;
using boost::regex;
using boost::regex_search;

// This list taken from GreenSQL
regex QueryRisk::sensitiveTablesRegex(
    ".*(customer|member|order|admin|user|permission|session).*",
    regex::perl | regex::icase
);
// This list taken from GreenSQL and appended by me
regex QueryRisk::bruteForceCommandsRegex(
    "^(mid|substr|substring|load_file|char)$",
    regex::perl | regex::icase
);
// This list taken from the MySQL manual; all the functions are synonymous
regex QueryRisk::userStatementsRegex(
    "^(current_user|session_user|system_user|user)$",
    regex::perl | regex::icase
);
// Fingerprinting functions for MySQL, taken from
// "SQL Injection Attacks and Defense" by Justin Clarke
regex QueryRisk::fingerprintingRegex(
    "^(schema|database|version|connection_id|last_insert_id|row_count)$",
    regex::perl | regex::icase
);
// String manipulation functions that can be used for detection evasion
regex QueryRisk::stringManipulationRegex(
    "^(concat|concatws|char|insert|hex|mid|replace|reverse|substr|substring)$",
    regex::perl | regex::icase
);
// Information schema is a special table that contains information about the
// database and tables in the database
regex QueryRisk::informationSchemaRegex(
    "^(information_schema|mysql)$",
    regex::perl | regex::icase
);
// Anything concerning the users table
const regex QueryRisk::userTableRegex(
    "(user|customer|member)",
    regex::perl | regex::icase
);

// These are just useful for doing case-insensitive compares
regex QueryRisk::ifRegex("^if$", regex::perl | regex::icase);
regex QueryRisk::benchmarkRegex("^benchmark$", regex::perl | regex::icase);


QueryRisk::QueryRisk()
    : queryType(TYPE_UNKNOWN)
    , multiLineComments(0)
    , hashComments(0)
    , dashDashComments(0)
    , mySqlComments(0)
    , mySqlVersionedComments(0)
    , sensitiveTables(0)
    , orStatements(0)
    , unionStatements(0)
    , unionAllStatements(0)
    , bruteForceCommands(0)
    , ifStatements(0)
    , hexStrings(0)
    , benchmarkStatements(0)
    , userStatements(0)
    , fingerprintingStatements(0)
    , mySqlStringConcat(0)
    , stringManipulationStatements(0)
    , alwaysTrueConditionals(0)
    , commentedConditionals(0)
    , commentedQuotes(0)
    , globalVariables(0)
    , joinStatements(0)
    , crossJoinStatements(0)
    , regexLength(0)
    , slowRegexes(0)
    , emptyPassword(PASSWORD_NOT_USED)
    , multipleQueries(false)
    , orderByNumber(false)
    , alwaysTrue(true)
    , informationSchema(false)
    , valid(true)
    , userTable(false)
{
}


QueryRisk::QueryRisk(const QueryRisk& rhs)
    : queryType(rhs.queryType)
    , multiLineComments(rhs.multiLineComments)
    , hashComments(rhs.hashComments)
    , dashDashComments(rhs.dashDashComments)
    , mySqlComments(rhs.mySqlComments)
    , mySqlVersionedComments(rhs.mySqlVersionedComments)
    , sensitiveTables(rhs.sensitiveTables)
    , orStatements(rhs.orStatements)
    , unionStatements(rhs.unionStatements)
    , unionAllStatements(rhs.unionAllStatements)
    , bruteForceCommands(rhs.bruteForceCommands)
    , ifStatements(rhs.ifStatements)
    , hexStrings(rhs.hexStrings)
    , benchmarkStatements(rhs.benchmarkStatements)
    , userStatements(rhs.userStatements)
    , fingerprintingStatements(rhs.fingerprintingStatements)
    , mySqlStringConcat(rhs.mySqlStringConcat)
    , stringManipulationStatements(rhs.stringManipulationStatements)
    , alwaysTrueConditionals(rhs.alwaysTrueConditionals)
    , commentedConditionals(rhs.commentedConditionals)
    , commentedQuotes(rhs.commentedQuotes)
    , globalVariables(rhs.globalVariables)
    , joinStatements(rhs.joinStatements)
    , crossJoinStatements(rhs.crossJoinStatements)
    , regexLength(rhs.regexLength)
    , slowRegexes(rhs.slowRegexes)
    , emptyPassword(rhs.emptyPassword)
    , multipleQueries(rhs.multipleQueries)
    , orderByNumber(rhs.orderByNumber)
    , alwaysTrue(rhs.alwaysTrue)
    , informationSchema(rhs.informationSchema)
    , valid(rhs.valid)
    , userTable(rhs.userTable)
{
}


void QueryRisk::checkTable(const string& table)
{
    if (regex_search(table, sensitiveTablesRegex))
    {
        ++sensitiveTables;
    }
    if (regex_search(table, userTableRegex))
    {
        userTable = true;
    }
}


void QueryRisk::checkDatabase(const string& database)
{
    if (regex_search(database, informationSchemaRegex))
    {
        informationSchema = true;
    }
}


void QueryRisk::updatePasswordRisk(const EmptyPassword ep)
{
    switch (emptyPassword)
    {
        case PASSWORD_EMPTY:
            // Nothing is riskier than an empty password, so there's nothing
            // to update
            return;
        case PASSWORD_NOT_EMPTY:
            switch (ep)
            {
                case PASSWORD_EMPTY:
                    emptyPassword = ep;
                    break;
                case PASSWORD_NOT_EMPTY:
                case PASSWORD_NOT_USED:
                default:
                    break;
            }
            break;
        case PASSWORD_NOT_USED:
            switch(ep)
            {
                case PASSWORD_EMPTY:
                case PASSWORD_NOT_EMPTY:
                    emptyPassword = ep;
                    break;
                case PASSWORD_NOT_USED:
                default:
                    break;
            }
            break;
        default:
            break;
    }
}


void QueryRisk::checkRegex(const string& regexStr)
{
    if (regexLength < regexStr.size())
    {
        regexLength = regexStr.size();
    }
    // Empty regexes or ones with just '%' shouldn't be a problem
    if (regexStr.size() > 1 && '%' == regexStr.at(0))
    {
        ++slowRegexes;
    }
}


void QueryRisk::checkFunction(const string& function)
{
    if (regex_search(function, bruteForceCommandsRegex))
    {
        ++bruteForceCommands;
    }

    if (regex_search(function, stringManipulationRegex))
    {
        ++stringManipulationStatements;
    }
    else if (regex_search(function, userStatementsRegex))
    {
        ++userStatements;
    }
    else if (regex_search(function, fingerprintingRegex))
    {
        ++fingerprintingStatements;
    }
    else if (regex_search(function, benchmarkRegex))
    {
        ++benchmarkStatements;
    }
    else if (regex_search(function, ifRegex))
    {
        ++ifStatements;
    }
}


std::ostream& operator<<(std::ostream& out, const QueryRisk& rhs)
{
    const char* shortDescriptions[] = {
        "multiLineComments",
        "hashComments",
        "dashDashComments",
        "mySqlComments",
        "mySqlVersionedComments",
        "sensitiveTables",
        "orStatements",
        "unionStatements",
        "unionAllStatements",
        "bruteForceCommands",
        "ifStatements",
        "hexStrings",
        "benchmarkStatements",
        "userStatements",
        "fingerprintingStatements",
        "mySqlStringConcat",
        "stringManipulationStatements",
        "alwaysTrueConditionals",
        "commentedConditionals",
        "commentedQuotes",
        "globalVariables",
        "joinStatements",
        "crossJoinStatements",
        "regexLength",
        "slowRegexes"
    };
    const size_t* shortAddresses[] = {
        &rhs.multiLineComments,
        &rhs.hashComments,
        &rhs.dashDashComments,
        &rhs.mySqlComments,
        &rhs.mySqlVersionedComments,
        &rhs.sensitiveTables,
        &rhs.orStatements,
        &rhs.unionStatements,
        &rhs.unionAllStatements,
        &rhs.bruteForceCommands,
        &rhs.ifStatements,
        &rhs.hexStrings,
        &rhs.benchmarkStatements,
        &rhs.userStatements,
        &rhs.fingerprintingStatements,
        &rhs.mySqlStringConcat,
        &rhs.stringManipulationStatements,
        &rhs.alwaysTrueConditionals,
        &rhs.commentedConditionals,
        &rhs.commentedQuotes,
        &rhs.globalVariables,
        &rhs.joinStatements,
        &rhs.crossJoinStatements,
        &rhs.regexLength,
        &rhs.slowRegexes
    };
    const int sizeShortDescriptions =
        sizeof(shortDescriptions) / sizeof(shortDescriptions[0]);
    const int sizeShortAddresses =
        sizeof(shortAddresses) / sizeof(shortAddresses[0]);
    assert(
        sizeShortDescriptions == sizeShortAddresses &&
        "Bad array descriptions for QueryRisk shorts"
    );
    for (int i = 0; i < sizeShortDescriptions; ++i)
    {
        if (*shortAddresses[i] > 0)
        {
            out << shortDescriptions[i] << ": " << *shortAddresses[i] << endl;
        }
    }

    switch (rhs.emptyPassword)
    {
    case QueryRisk::PASSWORD_EMPTY:
        out << "Password: empty" << endl;
        break;
    case QueryRisk::PASSWORD_NOT_EMPTY:
        out << "Password: not empty" << endl;
        break;
    case QueryRisk::PASSWORD_NOT_USED:
        out << "Password: not used" << endl;
        break;
    default:
        assert(false);
        Logger::log(Logger::ERROR) << "Unexpected enum value for password used";
        break;
    }

    const char* boolDescriptions[] = {
        "multipleQueries",
        "orderByNumber",
        "alwaysTrue",
        "informationSchema",
        "valid",
        "userTable"
    };
    const bool* boolAddresses[] = {
        &rhs.multipleQueries,
        &rhs.orderByNumber,
        &rhs.alwaysTrue,
        &rhs.informationSchema,
        &rhs.valid,
        &rhs.userTable
    };
    const int sizeBoolDescriptions =
        sizeof(boolDescriptions) / sizeof(boolDescriptions[0]);
    const int sizeBoolAddresses =
        sizeof(boolAddresses) / sizeof(boolAddresses[0]);
    assert(
        sizeBoolDescriptions == sizeBoolAddresses &&
        "Bad array descriptions for QueryRisk bools"
    );
    for (int i = 0; i < sizeBoolDescriptions; ++i)
    {
        if (*boolAddresses[i])
        {
            out << boolDescriptions[i] << ": " << *boolAddresses[i] << endl;
        }
    }

    return out;
}

std::ostream& operator<<(std::ostream& out, const QueryRisk::QueryType qt)
{
    switch (qt)
    {
        case QueryRisk::TYPE_UNKNOWN:
            out << "TYPE_UNKNOWN";
            break;
        case QueryRisk::TYPE_SELECT:
            out << "TYPE_SELECT";
            break;
        case QueryRisk::TYPE_INSERT:
            out << "TYPE_INSERT";
            break;
        case QueryRisk::TYPE_UPDATE:
            out << "TYPE_UPDATE";
            break;
        case QueryRisk::TYPE_DELETE:
            out << "TYPE_DELETE";
            break;
        case QueryRisk::TYPE_TRANSACTION:
            out << "TYPE_TRANSACTION";
            break;
        case QueryRisk::TYPE_SET:
            out << "TYPE_SET";
            break;
        case QueryRisk::TYPE_EXPLAIN:
            out << "TYPE_EXPLAIN";
            break;
        case QueryRisk::TYPE_SHOW:
            out << "TYPE_SHOW";
            break;
        case QueryRisk::TYPE_DESCRIBE:
            out << "TYPE_DESCRIBE";
            break;
        case QueryRisk::TYPE_LOCK:
            out << "TYPE_LOCK";
            break;
        case QueryRisk::TYPE_USE:
            out << "TYPE_USE";
            break;
        default:
            out << "Unknown QueryType value (" << static_cast<int>(qt) << ')';
            break;
    }
    return out;
}


bool operator==(const QueryRisk& qr1, const QueryRisk& qr2)
{
    return qr1.queryType == qr2.queryType
        && qr1.multiLineComments == qr2.multiLineComments
        && qr1.hashComments == qr2.hashComments
        && qr1.dashDashComments == qr2.dashDashComments
        && qr1.mySqlComments == qr2.mySqlComments
        && qr1.mySqlVersionedComments == qr2.mySqlVersionedComments
        && qr1.sensitiveTables == qr2.sensitiveTables
        && qr1.orStatements == qr2.orStatements
        && qr1.unionStatements == qr2.unionStatements
        && qr1.unionAllStatements == qr2.unionAllStatements
        && qr1.bruteForceCommands == qr2.bruteForceCommands
        && qr1.ifStatements == qr2.ifStatements
        && qr1.hexStrings == qr2.hexStrings
        && qr1.benchmarkStatements == qr2.benchmarkStatements
        && qr1.userStatements == qr2.userStatements
        && qr1.fingerprintingStatements == qr2.fingerprintingStatements
        && qr1.mySqlStringConcat == qr2.mySqlStringConcat
        && qr1.stringManipulationStatements == qr2.stringManipulationStatements
        && qr1.alwaysTrueConditionals == qr2.alwaysTrueConditionals
        && qr1.commentedConditionals == qr2.commentedConditionals
        && qr1.commentedQuotes == qr2.commentedQuotes
        && qr1.globalVariables == qr2.globalVariables
        && qr1.joinStatements == qr2.joinStatements
        && qr1.crossJoinStatements == qr2.crossJoinStatements
        && qr1.regexLength == qr2.regexLength
        && qr1.slowRegexes == qr2.slowRegexes
        && qr1.emptyPassword == qr2.emptyPassword
        && qr1.multipleQueries == qr2.multipleQueries
        && qr1.orderByNumber == qr2.orderByNumber
        && qr1.alwaysTrue == qr2.alwaysTrue
        && qr1.informationSchema == qr2.informationSchema
        && qr1.valid == qr2.valid
        && qr1.userTable == qr2.userTable
    ;
}


size_t hash_value(const QueryRisk& qr)
{
    // Sdbm hash
    size_t hash = 0;
    const char* memPtr = reinterpret_cast<const char*>(&qr);
    for (size_t i = 0; i < sizeof(qr); ++i)
    {
        hash = *memPtr + (hash << 6) + (hash << 16) - hash;
        ++memPtr;
    }
    assert(
        memPtr == reinterpret_cast<const char*>(&qr + 1) &&
        "Pointer should end up at the end of the QueryRisk"
    );
    return hash;
}
