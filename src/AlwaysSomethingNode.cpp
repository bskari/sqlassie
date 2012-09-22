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

#include "AlwaysSomethingNode.hpp"
#include "ComparisonNode.hpp"
#include "sqlParser.h"
#include "QueryRisk.hpp"

#include <ostream>
#include <string>

using std::string;
using std::ostream;


AlwaysSomethingNode::AlwaysSomethingNode(const bool always)
    : ExpressionNode("AlwaysSomething")
    , always_(always)
{
}


AlwaysSomethingNode::~AlwaysSomethingNode()
{
}


AstNode* AlwaysSomethingNode::copy() const
{
    AlwaysSomethingNode* const temp = new AlwaysSomethingNode(always_);
    AstNode::addCopyOfChildren(temp);
    return temp;
}


bool AlwaysSomethingNode::isAlwaysTrueOrFalse() const
{
    return true;
}


bool AlwaysSomethingNode::isAlwaysTrue() const
{
    return always_;
}


QueryRisk::EmptyPassword AlwaysSomethingNode::emptyPassword() const
{
    return QueryRisk::PASSWORD_NOT_USED;
}


bool AlwaysSomethingNode::resultsInValue() const
{
    return false;
}


string AlwaysSomethingNode::getValue() const
{
    assert(resultsInValue());

    if (isAlwaysTrue())
    {
        return "1";
    }
    else
    {
        return "0";
    }
}


void AlwaysSomethingNode::print(
    std::ostream& out,
    const int depth,
    const char indent
) const
{
    for (int i = 0; i < depth; ++i)
    {
        out << indent;
    }

    out << "AlwaysSomethingNode:";
    if (isAlwaysTrue())
    {
        out << "true";
    }
    else
    {
        out << "false";
    }
    out << '\n';

    printChildren(out, depth + 1, indent);
}
