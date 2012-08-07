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

#include "ExpressionNode.hpp"
#include "Logger.hpp"
#include "MySqlConstants.hpp"
#include "NegationNode.hpp"
#include "nullptr.hpp"
#include "QueryRisk.hpp"

#include <ostream>
#include <string>

using std::ostream;
using std::string;


NegationNode::NegationNode(const ExpressionNode* const expression)
    : ExpressionNode("Negation")
    , expression_(expression)
{
}


NegationNode::~NegationNode()
{
    delete expression_;
}


AstNode* NegationNode::copy() const
{
    NegationNode* const temp = new NegationNode(expression_);
    AstNode::addCopyOfChildren(temp);
    return temp;
}


bool NegationNode::isAlwaysTrueOrFalse() const
{
    return expression_->isAlwaysTrueOrFalse();
}


bool NegationNode::isAlwaysTrue() const
{
    if (expression_->isAlwaysTrueOrFalse())
    {
        return !expression_->isAlwaysTrue();
    }
    return false;
}


QueryRisk::EmptyPassword NegationNode::emptyPassword() const
{
    return QueryRisk::PASSWORD_NOT_USED;
}


bool NegationNode::resultsInValue() const
{
    return expression_->resultsInValue();
}


string NegationNode::getValue() const
{
    assert(resultsInValue());
    if ("0.0" == expression_->getValue() || "0" == expression_->getValue())
    {
        return "1";
    }
    return "0";
}


void NegationNode::print(
    ostream& out,
    const int depth,
    const char indent
) const
{
    for (int i = 0; i < depth; ++i)
    {
        out << indent;
    }
    out << name_ << '\n';
    expression_->print(out, depth + 1, indent);
}
