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
#ifndef SRC_TESTS_TESTPARSER_HPP_
#define SRC_TESTS_TESTPARSER_HPP_

/**
 * Tests that some collected, known queries that are stored in files in the
 * /queries directory will successfully parse.
 */
void testParseKnownGoodQueries();

/**
 * Tests that safe queries don't produce any risks.
 */
void testQueryRiskSafe();

/**
 * Tests that the risk of certain comment types are correctly identified.
 */
void testQueryRiskComments();

/**
 * Tests that the risk of always true statements in queries are correctly
 * identified.
 */
void testQueryRiskAlwaysTrue();

/**
 * Test different kinds of select items.
 */
void testSelectItems();

/**
 * Test that the type of query is being set.
 */
void testQueryType();

#endif  // SRC_TESTS_TESTPARSER_HPP_
