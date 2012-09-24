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
#include "NullNode.hpp"
#include "QueryRisk.hpp"
#include "sqlParser.h"

#include <ostream>
#include <string>

using std::ostream;
using std::string;


NullNode::NullNode()
    : ExpressionNode("Null")
{
}


NullNode::~NullNode()
{
}


AstNode* NullNode::copy() const
{
    NullNode* const temp = new NullNode();
    AstNode::addCopyOfChildren(temp);
    return temp;
}


bool NullNode::isAlwaysTrueOrFalse() const
{
    return true;
}


bool NullNode::isAlwaysTrue() const
{
    return false;
}


bool NullNode::resultsInValue() const
{
    return false;
}


string NullNode::getValue() const
{
    assert(resultsInValue());
    return "";
}


void NullNode::print(
    ostream& out,
    const int depth,
    const char indent
) const
{
    for (int i = 0; i < depth; ++i)
    {
        out << indent;
    }
    out << "NULL\n";
}
