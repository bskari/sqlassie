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

#include "AstNode.hpp"
#include "Logger.hpp"
#include "OperatorNode.hpp"

#include <cassert>


OperatorNode::OperatorNode(const int operatorToken)
    : AstNode("Operator")
    , operator_(operatorToken)
{
}


OperatorNode::~OperatorNode()
{
}


AstNode* OperatorNode::copy() const
{
    OperatorNode* const temp = new OperatorNode(operator_);
    assert(children_.empty());
    return temp;
}


int OperatorNode::getOperator() const
{
    return operator_;
}


void OperatorNode::print(
    std::ostream& out,
    const int depth,
    const char indent
) const
{
    for (int i = 0; i < depth; ++i)
    {
        out << indent;
    }
    // I'm only expecting to use this for debugging, so printing out the
    // token value instead of the operator itself isn't a bad plan
    out << name_ << ": op(" << operator_ << ")\n";
    printChildren(out, depth + 1, indent);
}
