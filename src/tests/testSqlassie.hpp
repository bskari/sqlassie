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
#ifndef SRC_TESTS_TESTSQLASSIE_HPP_
#define SRC_TESTS_TESTSQLASSIE_HPP_

/**
 * Makes sure that safe queries are forwarded.
 */
void testSafeQueriesForwarded();

/**
 * Makes sure that dangerous SELECT queries return fake empty sets.
 */
void testDangerousSelectsAreBlocked();

/**
 * Makes sure that dangerous INSERT, UPDATE, and DELETE queries return fake OK
 * packets.
 */
void testDangerousCommandsAreBlocked();

/**
 * Makes sure that invalid commands that parse correctly return fake empty set
 * packets or OK packets.
 */
void testSemanticallyInvalidCommandsAreBlocked();

/**
 * Makes sure that queries that fail to parse return empty set packets or OK
 * packets.
 */
void testSyntacticallyInvalidCommandsAreBlocked();

#endif  // SRC_TESTS_TESTSQLASSIE_HPP_
