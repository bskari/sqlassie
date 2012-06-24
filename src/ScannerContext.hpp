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

#ifndef SRC_SCANNERCONTEXT_HPP_
#define SRC_SCANNERCONTEXT_HPP_

#include <stack>
#include <string>

#include "QueryRisk.hpp"

struct ScannerContext
{
    std::stack<std::string> identifiers;
    std::string identifier;
    std::stack<std::string> quotedStrings;
    std::string quotedString;
    // Using strings instead of ints for this stack because otherwise I would
    // get weird segmentation fault errors whenever I'd try to pop it
    std::stack<std::string> numbers;
    std::stack<std::string> hexNumbers;

    QueryRisk* const qrPtr;

    ScannerContext(QueryRisk* const qrPtr);
    ~ScannerContext();

private:
    // Hidden methods
    ScannerContext(const ScannerContext& rhs);
    ScannerContext& operator=(const ScannerContext& rhs);
};

#endif  // SRC_SCANNERCONTEXT_HPP_
