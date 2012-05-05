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
#ifndef SRC_TESTS_TESTMYSQLCONSTANTS_HPP_
#define SRC_TESTS_TESTMYSQLCONSTANTS_HPP_

/**
 * Tests that my implementation of the soundex algorithm, used in SOUNDS LIKE
 * comparisons, matches MySQL''s implementation.
 */
void testSoundex();


/**
 * Tests that my function to convert MySQL regular expressions into Perl
 * regular expressions that I can use with Boost's regular expression library
 * works.
 */
void testConvertRegex();

#endif  // SRC_TESTS_TESTMYSQLCONSTANTS_HPP_
