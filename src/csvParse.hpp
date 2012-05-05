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

#ifndef SRC_CSVPARSE_HPP_
#define SRC_CSVPARSE_HPP_

#include <vector>
#include <iostream>
#include <sstream>
#include <cassert>
#include <cstdlib>
#include <exception>
#include <limits>

/**
 * Methods to parse comma separated value files.
 * @author Brandon Skari
 * @date December 14 2010
 */


template<typename T>
void parseCsvFile(std::vector<std::vector<T> >& values, std::istream& in)
{
    char c;
    std::vector<T> line;
    T value;
    std::stringstream stream;
    bool newLine = true;

    in.get(c);
    while (!in.eof())
    {
        switch(c)
        {
            case ',':
                stream >> value;
                stream.clear();
                line.push_back(value);
                break;
            // Ignore comments
            case '#':
                in.ignore(std::numeric_limits<int>::max(), '\n');
                if (newLine)
                {
                    break;
                }
            case '\n':
                stream >> value;
                stream.clear();
                line.push_back(value);
                values.push_back(line);
                line.clear();
                newLine = true;
                break;
            default:
                newLine = false;
                stream << c;
        }
        in.get(c);
    }
}


// Template specialization for ints
// This results in about a 40% speedup
template<>
void parseCsvFile(std::vector<std::vector<int32_t> >& values, std::istream& in)
{
    std::vector<int32_t> line;
    int32_t value;
    char digits[12]; // -2147483647 '\0'
    int32_t charCount = 0;
    char* lastParsed;
    bool newLine = true;

    in.get(digits[charCount]);
    while (!in.eof())
    {
        if (
            static_cast<unsigned int32_t>(charCount) >
                sizeof(digits) / sizeof(digits[0])
        )
        {
            throw std::exception();
        }
        switch(digits[charCount])
        {
            case ',':
                digits[charCount] = '\0';
                charCount = 0;
                value = strtol(digits, &lastParsed, 10);
                if ('\0' != *lastParsed)
                {
                    throw std::exception();
                }
                line.push_back(value);
                break;
            // Ignore comments
            case '#':
                in.ignore(std::numeric_limits<int32_t>::max(), '\n');
                if (newLine)
                {
                    break;
                }
            case '\n':
                digits[charCount] = '\0';
                charCount = 0;
                value = strtol(digits, &lastParsed, 10);
                if ('\0' != *lastParsed)
                {
                    throw std::exception();
                }
                line.push_back(value);
                values.push_back(line);
                line.clear();
                newLine = true;
                break;
            default:
                newLine = false;
                ++charCount;
        }
        in.get(digits[charCount]);
    }
}

#endif  // SRC_CSVPARSE_HPP_
