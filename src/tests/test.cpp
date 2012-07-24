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

#include <boost/test/included/unit_test.hpp>
#include <string>

namespace test = boost::unit_test;
using std::string;


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

    // Tests from testParser.cpp
    test::framework::master_test_suite().add(
        BOOST_TEST_CASE(testParseKnownGoodQueries)
    );
    test::framework::master_test_suite().add(
        BOOST_TEST_CASE(testQueryType)
    );

    // Tests from testQueryRiskParser.cpp
    test::framework::master_test_suite().add(
        BOOST_TEST_CASE(testQueryRiskSafe)
    );
    test::framework::master_test_suite().add(
        BOOST_TEST_CASE(testQueryRiskComments)
    );
    test::framework::master_test_suite().add(
        BOOST_TEST_CASE(testQueryRiskAlwaysTrue)
    );
    test::framework::master_test_suite().add(
        BOOST_TEST_CASE(testQueryRiskGlobalVariables)
    );
    test::framework::master_test_suite().add(
        BOOST_TEST_CASE(testQueryRiskSensitiveTables)
    );

    // Tests from testNode.cpp
    test::framework::master_test_suite().add(BOOST_TEST_CASE(testAstNode));
    test::framework::master_test_suite().add(
        BOOST_TEST_CASE(testAlwaysSomethingNode)
    );
    test::framework::master_test_suite().add(
        BOOST_TEST_CASE(testComparisonNode)
    );

    // Tests from testMySqlConstants.cpp
    test::framework::master_test_suite().add(BOOST_TEST_CASE(testSoundex));
    test::framework::master_test_suite().add(
        BOOST_TEST_CASE(testConvertRegex)
    );

    // Tests from testQueryWhitelist.cpp
    test::framework::master_test_suite().add(
        BOOST_TEST_CASE(testParseWhitelist)
    );
    test::framework::master_test_suite().add(
        BOOST_TEST_CASE(testRiskWhitelist)
    );

    // Tests from testScanner.cpp
    test::framework::master_test_suite().add(
        BOOST_TEST_CASE(testAllTokensScan)
    );
    test::framework::master_test_suite().add(
        BOOST_TEST_CASE(testScanNumbers)
    );

    return 0;
}
