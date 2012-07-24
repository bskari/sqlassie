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
#ifndef SRC_TESTS_TESTSCANNER_HPP_
#define SRC_TESTS_TESTSCANNER_HPP_

/**
 * Makes sure that all of the terminal tokens defined in the grammar rules of
 * the parser will be returned by the scanner.
 */
void testAllTokensScan();

/**
 * Test that various number types are correctly identified.
 */
void testScanNumbers();

#endif  // SRC_TESTS_TESTSCANNER_HPP_
