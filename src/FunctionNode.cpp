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

#include "ComparisonNode.hpp"
#include "FunctionNode.hpp"
#include "QueryRisk.hpp"
#include "sqlParser.h"

#include <ostream>
#include <string>

using std::ostream;
using std::string;


FunctionNode::FunctionNode(const string& functionName)
    : ExpressionNode("Function")
    , functionName_(functionName)
{
}


FunctionNode::~FunctionNode()
{
}


AstNode* FunctionNode::copy() const
{
    FunctionNode* const temp = new FunctionNode(functionName_);
    AstNode::addCopyOfChildren(temp);
    return temp;
}


bool FunctionNode::isAlwaysTrue() const
{
    return false;
}


bool FunctionNode::anyIsAlwaysTrue() const
{
    return FunctionNode::isAlwaysTrue();
}


QueryRisk::EmptyPassword FunctionNode::emptyPassword() const
{
    return QueryRisk::PASSWORD_NOT_USED;
}


bool FunctionNode::resultsInValue() const
{
    return false;
}


string FunctionNode::getValue() const
{
    assert(resultsInValue());
    return "";
}


void FunctionNode::print(
    ostream& out,
    const int depth,
    const char indent
) const
{
    for (int i = 0; i < depth; ++i)
    {
        out << indent;
    }
    out << functionName_ << '\n';
    printChildren(out, depth + 1, indent);
}
