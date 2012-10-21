/*
 * SQLassie - database firewall
 * Copyright (C) 2012 Brandon Skari <brandon@skari.org>
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

#include "IndeterminateNode.hpp"

#include <ostream>
#include <string>

using std::string;
using std::ostream;


IndeterminateNode::IndeterminateNode()
    : ExpressionNode("Indeterminate")
{
}


IndeterminateNode::~IndeterminateNode()
{
}


AstNode* IndeterminateNode::copy() const
{
    IndeterminateNode* const temp = new IndeterminateNode();
    AstNode::addCopyOfChildren(temp);
    return temp;
}


bool IndeterminateNode::isAlwaysTrueOrFalse() const
{
    return false;
}


bool IndeterminateNode::isAlwaysTrue() const
{
    assert(isAlwaysTrueOrFalse());
    return false;
}


bool IndeterminateNode::resultsInValue() const
{
    return false;
}


string IndeterminateNode::getValue() const
{
    assert(resultsInValue());
    return "";
}


void IndeterminateNode::print(
    std::ostream& out,
    const int depth,
    const char indent
) const
{
    for (int i = 0; i < depth; ++i)
    {
        out << indent;
    }

    out << "IndeterminateNode\n";

    printChildren(out, depth + 1, indent);
}
