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
#include "ParserInterface.hpp"
#include "QueryRisk.hpp"
#include "SensitiveNameChecker.hpp"

#include <cassert>
#include <fstream>
#include <iostream>
#include <string>

using std::cerr;
using std::cin;
using std::cout;
using std::endl;
using std::ifstream;
using std::istream;
using std::string;

/**
 * Reads in queries and logs information about them.
 * @author Brandon Skari
 * @date December 13 2010
 */


int main(int argc, char* argv[])
{
    Logger::initialize();
    SensitiveNameChecker::initialize();
    SensitiveNameChecker::get().setPasswordSubstring("password");
    SensitiveNameChecker::get().setUserSubstring("user");
    assert(34 == sizeof(QueryRisk) &&
"QueryStatistics size has changed; did you add more features?\n\
If so, you need to update queryStatistics.cpp");

    ifstream fin;
    if (argc > 1)
    {
        fin.open(argv[1]);
    }
    istream& stream = (fin.is_open() ? fin : cin);
    if (argc > 1 && !fin)
    {
        cerr << "Unable to open file '" << argv[1] << "', aborting" << endl;
        return 0;
    }

    cout << "# Multi-line comments, hash comments, dash dash comments, \
MySQL comments, MySQL versioned comments, risky tables, or statements, \
union statements, union all statements, brute force commands, if statements, \
hex strings, benchmark statements, user statements, empty password, \
multiple queries, order by number, always true, information schema" << endl;

    while (!stream.eof())
    {
        string query;
        getline(stream, query);

        if (0 == query.length())
        {
            continue;
        }

        QueryRisk qr;
        ParserInterface parser(query);

        const int status = parser.parse(&qr);

        // If the query was successfully parsed (i.e. was a valid query)'
        if (0 == status && qr.valid)
        {
            // Don't print valid lines if we're reading from a file
            cout << qr << endl;
        }
        else
        {
            cerr << "Bad query: " << query << endl;
            Logger::log(Logger::ERROR) << "Invalid query provided!";
            assert(false);
        }
    }
    return 0;
}
