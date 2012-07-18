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

#include "AstNode.hpp"
#include "QueryRisk.hpp"

struct ScannerContext
{
    std::string identifier;
    std::string quotedString;

    QueryRisk* const qrPtr;

    // To prevent memory leaks in the case of parse failures, I'll push and
    // pop AST nodes here instead of directly returning them as part of the
    // parser's rules. I don't care about error recovery when parsing fails
    // anyway, and I don't feel like adding error handling just for memory.
    std::stack<AstNode*> nodes;

    ScannerContext(QueryRisk* const qrPtr);
    ~ScannerContext();

private:
    // Hidden methods
    ScannerContext(const ScannerContext& rhs);
    ScannerContext& operator=(const ScannerContext& rhs);
};

#endif  // SRC_SCANNERCONTEXT_HPP_
