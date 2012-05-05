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

#include "csvParse.hpp"

#include <iostream>
#include <fstream>
#include <vector>
#include <boost/foreach.hpp>

using std::cerr;
using std::cout;
using std::endl;
using std::ifstream;
using std::vector;

/**
 * Reads in frequencies from a comma separated value and computes propabilities
 * and pairwise conditional probabilities.
 * @author Brandon Skari
 * @date December 14 2010
 */

typedef vector<int> VECTOR_INT;

int main(int argc, char* argv[])
{
    if (2 != argc)
    {
        cerr << "Usage: " << argv[0] << " <csv file>" << endl;
        return 1;
    }

    ifstream fin(argv[1]);
    if (!fin)
    {
        cerr << "Unable to open file " << argv[1] << endl;
        return 1;
    }

    vector<vector<int> > values;
    try
    {
        parseCsvFile(values, fin);
    }
    catch(...)
    {
        cerr << "Error parsing file" << endl;
        return 1;
    }
    fin.close();

    const int numberQueries = values.size();
    vector<int> totals;
    totals.resize(values.at(0).size(), 0);


    BOOST_FOREACH(VECTOR_INT vec, values)
    {
        for (size_t i = 0; i < vec.size(); ++i)
        {
            if (vec.at(i) > 0)
            {
                ++totals.at(i);
            }
        }
    }

    // Single probabilities
    for (size_t i = 0; i < totals.size(); ++i)
    {
        cout << "P("
            << i + 1
            << ") = "
            << static_cast<double>(totals.at(i)) / numberQueries
            << endl;
    }

    for (size_t given = 0; given < values.at(0).size(); ++given)
    {
        vector<int> conditionals;
        vector<int> conditionalsCount;
        conditionals.resize(values.at(0).size(), 0);
        conditionalsCount.resize(values.at(0).size(), 0);
        BOOST_FOREACH(VECTOR_INT vec, values)
        {
            for (size_t i = 0; i < vec.size(); ++i)
            {
                if (vec.at(given) > 0)
                {
                    ++conditionalsCount.at(i);
                    if (vec.at(i) > 0)
                    {
                        ++conditionals.at(i);
                    }
                }
            }
        }

        for (size_t i = 0; i < conditionals.size(); ++i)
        {
            if (conditionals.at(i) < 0.00001)
            {
                continue;
            }
            cout << "P("
                << i + 1
                << '|'
                << given + 1
                << ") = "
                << static_cast<double>(
                        conditionals.at(i)
                    ) / conditionalsCount.at(i)
                << endl;
        }
    }

    return 0;
}
