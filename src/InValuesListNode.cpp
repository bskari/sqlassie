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
#include "SensitiveNameChecker.hpp"
#include "InValuesListNode.hpp"
#include "nullptr.hpp"
#include "QueryRisk.hpp"

#include <boost/cast.hpp>
#include <boost/regex.hpp>
#include <cassert>
#include <string>
#include <vector>

using boost::polymorphic_downcast;
using boost::regex;
using boost::regex_match;
using std::string;
using std::vector;


InValuesListNode::InValuesListNode(const ExpressionNode* const expression)
    : ExpressionNode("InValuesList")
    , expression_(expression)
{
}


InValuesListNode::~InValuesListNode()
{
    delete expression_;
}


AstNode* InValuesListNode::copy() const
{
    InValuesListNode* const temp = new InValuesListNode(expression_);
    AstNode::addCopyOfChildren(temp);
    return temp;
}


bool InValuesListNode::isAlwaysTrueOrFalse() const
{
    if (!expression_->resultsInValue() && !expression_->resultsInString())
    {
        return false;
    }
    const string firstExpression(expression_->getValue());

    // If all the elements are values or strings, or the expression matches
    // one of the values, then we can determine truthiness.
    /// TODO(bskari|2012-09-02) Save this data so I don't have to recompute it
    /// when I call isAlwaysTrue
    bool allValuesOrStrings = true;
    vector<const AstNode*>::const_iterator end(children_.end());
    for (
        vector<const AstNode*>::const_iterator i(children_.begin());
        i != end;
        ++i
    )
    {
        const ExpressionNode* const expr =
            polymorphic_downcast<const ExpressionNode*>(*i);

        if (!expr->resultsInValue() && !expr->resultsInString())
        {
            allValuesOrStrings = false;
        }
        else if (firstExpression == expr->getValue())
        {
            return true;
        }
    }
    return allValuesOrStrings;
}


bool InValuesListNode::isAlwaysTrue() const
{
    if (!expression_->resultsInValue() && !expression_->resultsInString())
    {
        return false;
    }
    const string firstExpression(expression_->getValue());

    vector<const AstNode*>::const_iterator end(children_.end());
    for (
        vector<const AstNode*>::const_iterator i(children_.begin());
        i != end;
        ++i
    )
    {
        const ExpressionNode* const expr =
            polymorphic_downcast<const ExpressionNode*>(*i);

        if (
            (
                expr->resultsInValue()
                || expr->resultsInString()
            )
            && firstExpression == expr->getValue()
        )
        {
            return true;
        }
    }
    return false;
}


bool InValuesListNode::resultsInValue() const
{
    return expression_->resultsInValue();
}


string InValuesListNode::getValue() const
{
    assert(resultsInValue());

    if (isAlwaysTrue())
    {
        return "1";
    }
    return "0";
}


void InValuesListNode::print(
    std::ostream& out,
    const int depth,
    const char indent
) const
{
    for (int i = 0; i < depth; ++i)
    {
        out << indent;
    }
    out << name_ << ":\n{\n" << *expression_;

    for (int i = 0; i < depth; ++i)
    {
        out << indent;
    }
    out << "In\n";

    printChildren(out, depth + 1, indent);
    for (int i = 0; i < depth; ++i)
    {
        out << indent;
    }
    out << "}\n";
}
