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

#include "../SensitiveNameChecker.hpp"
#include "../Logger.hpp"
#include "../nullptr.hpp"
#include "../QueryWhitelist.hpp"

#include "testMySqlConstants.hpp"
#include "testNode.hpp"
#include "testParser.hpp"
#include "testQueryRisk.hpp"
#include "testQueryWhitelist.hpp"
#include "testScanner.hpp"
#include "testSqlassie.hpp"

#include <boost/test/included/unit_test.hpp>
#include <string>

namespace test = boost::unit_test;
using std::string;

#define STR_EXPAND(tok) #tok
#define STR(tok) STR_EXPAND(tok)
#define FD( function) FunctionDescription(function, STR(function))


test::test_suite* init_unit_test_suite(int, char*[])
{
    Logger::initialize();
    Logger::setLevel(Logger::ALL);
    SensitiveNameChecker::initialize();
    SensitiveNameChecker::get().setPasswordSubstring("password");
    SensitiveNameChecker::get().setUserSubstring("user");

    // Set up blocking for the whitelist test
    string parseWhitelistFilename("../src/tests/parseWhitelist.mysql");
    string blockWhitelistFilename("../src/tests/blockWhitelist.mysql");
    QueryWhitelist::initialize(
        &parseWhitelistFilename,
        &blockWhitelistFilename
    );

    Logger::setLevel(Logger::ALL);

    typedef void(*testFunction)(void);
    struct FunctionDescription
    {
        FunctionDescription(testFunction function, const char* name)
            : function_(function)
            , name_(name)
        {
        }
        testFunction function_;
        const string name_;
    };

    FunctionDescription functions[] = {
        // Tests from testParser.cpp
        FD(testParseKnownGoodQueries),
        FD(testQueryType),
        // Tests from testQueryRisk.cpp
        FD(testQueryRiskSafe),
        FD(testQueryRiskComments),
        FD(testQueryRiskSensitiveTables),
        FD(testQueryRiskOrStatements),
        FD(testQueryRiskUnionStatements),
        FD(testQueryRiskUnionAllStatements),
        FD(testQueryRiskBruteForceCommands),
        FD(testQueryRiskIfStatements),
        FD(testQueryRiskHexStrings),
        FD(testQueryRiskBenchmarkStatements),
        FD(testQueryRiskUserStatements),
        FD(testQueryRiskFingerprintingStatements),
        FD(testQueryRiskMySqlStringConcat),
        FD(testQueryRiskStringManipulationStatements),
        FD(testQueryRiskAlwaysTrueConditional),
        FD(testQueryRiskCommentedConditionals),
        FD(testQueryRiskCommentedQuotes),
        FD(testQueryRiskGlobalVariables),
        FD(testQueryRiskJoinStatements),
        FD(testQueryRiskCrossJoinStatements),
        FD(testQueryRiskRegexLength),
        FD(testQueryRiskSlowRegexes),
        FD(testQueryRiskEmptyPassword),
        FD(testQueryRiskMultipleQueries),
        FD(testQueryRiskOrderByNumber),
        FD(testQueryRiskAlwaysTrue),
        FD(testQueryRiskInformationSchema),
        FD(testQueryRiskValid),
        FD(testQueryRiskUserTable),
        // Tests from testNode.cpp
        FD(testAstNode),
        FD(testAlwaysSomethingNode),
        FD(testComparisonNode),
        // Tests from testMySqlConstants.cpp
        FD(testSoundex),
        FD(testConvertRegex),
        // Tests from testQueryWhitelist.cpp
        FD(testParseWhitelist),
        FD(testRiskWhitelist),
        // Tests from testScanner.cpp
        FD(testAllTokensScan),
        FD(testScanNumbers),
        FD(testScanComments),
        // Tests from testSqlassie.cpp
        FD(testSafeQueriesForwarded),
        FD(testDangerousSelectsAreBlocked),
        FD(testDangerousCommandsAreBlocked),
        FD(testSemanticallyInvalidCommandsAreBlocked),
        FD(testSyntacticallyInvalidCommandsAreBlocked)
    };

    for (size_t i = 0; i < sizeof(functions) / sizeof(functions[0]); ++i)
    {
        test::framework::master_test_suite().add(
            test::make_test_case(
                test::callback0<>(functions[i].function_),
                test::literal_string(
                    functions[i].name_.c_str(),
                    functions[i].name_.length()
                )
            )
        );
    }

    return 0;
}
