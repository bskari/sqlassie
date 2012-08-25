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
#ifndef SRC_TESTS_TESTQUERYRISK_HPP_
#define SRC_TESTS_TESTQUERYRISK_HPP_

/**
 * Tests that safe queries don't produce any risks.
 */
void testQueryRiskSafe();

/**
 * Tests that the risk of certain comment types is correctly identified.
 */
void testQueryRiskComments();

/**
 * Tests that various query risks are being correctly determined and accounted
 * for by the parser.
 */
///@{
void testQueryRiskSensitiveTables();
void testQueryRiskOrStatements();
void testQueryRiskUnionStatements();
void testQueryRiskUnionAllStatements();
void testQueryRiskBruteForceCommands();
void testQueryRiskIfStatements();
void testQueryRiskHexStrings();
void testQueryRiskBenchmarkStatements();
void testQueryRiskUserStatements();
void testQueryRiskFingerprintingStatements();
void testQueryRiskMySqlStringConcat();
void testQueryRiskStringManipulationStatements();
void testQueryRiskAlwaysTrueConditional();
void testQueryRiskCommentedConditionals();
void testQueryRiskCommentedQuotes();
void testQueryRiskGlobalVariables();
void testQueryRiskJoinStatements();
void testQueryRiskCrossJoinStatements();
void testQueryRiskRegexLength();
void testQueryRiskSlowRegexes();
void testQueryRiskEmptyPassword();
void testQueryRiskMultipleQueries();
void testQueryRiskOrderByNumber();
void testQueryRiskAlwaysTrue();
void testQueryRiskInformationSchema();
void testQueryRiskValid();
void testQueryRiskUserTable();
///@}

#endif  // SRC_TESTS_TESTQUERYRISK_HPP_
