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

#include "ComparisonNode.hpp"
#include "ExpressionNode.hpp"
#include "Logger.hpp"
#include "MySqlConstants.hpp"
#include "nullptr.hpp"
#include "QueryRisk.hpp"
#include "SensitiveNameChecker.hpp"
#include "sqlParser.h"

#include <boost/cast.hpp>
#include <boost/regex.hpp>
#include <ctype.h>
#include <ostream>
#include <string>

using boost::polymorphic_downcast;
using boost::regex;
using boost::regex_replace;
using boost::regex_match;
using std::ostream;
using std::string;


ComparisonNode::ComparisonNode(
    const ExpressionNode* const expr1,
    const int compareType,
    const ExpressionNode* const expr2
)
    : ExpressionNode("Comparison")
    , expr1_(expr1)
    , compareType_(compareType)
    , expr2_(expr2)
{
}


ComparisonNode::~ComparisonNode()
{
    delete expr1_;
    delete expr2_;
}


AstNode* ComparisonNode::copy() const
{
    ComparisonNode* const temp = new ComparisonNode(
        expr1_,
        compareType_,
        expr2_
    );
    AstNode::addCopyOfChildren(temp);
    return temp;
}


bool ComparisonNode::isAlwaysTrue() const
{
    if (BETWEEN == compareType_)
    {
        // BETWEEN is logically equivalent to
        // (min[expr1_] <= expr[child0] AND expr[child0] <= max[expr2_])
        assert(
            1 == children_.size()
            && "BETWEEN comparisons should have 1 child"
        );
        const ExpressionNode* const expr =
            polymorphic_downcast<const ExpressionNode*>(children_.at(0));
        // We only care about numbers; anything else (like identifiers) is
        // assumed to not always be true
        if (
            expr1_->resultsInValue() && expr2_->resultsInValue()
        )
        {
            return expr1_->getValue() <= expr->getValue()
                && expr->getValue() <= expr2_->getValue();
        }
    }

    assert(0 == children_.size() && "ComparisonNode should have no children");

    // Both either need to result in values or strings
    /// @TODO(bskari|2012-07-29) Handle things like (0 == '0')
    if (
        (!expr1_->resultsInValue() && !expr2_->resultsInValue())
        && (!expr1_->resultsInString() && !expr2_->resultsInString())
    )
    {
        return false;
    }

    if (EQ == compareType_)
    {
        return expr1_->getValue() == expr2_->getValue();
    }
    else if (LT == compareType_)
    {
        return expr1_->getValue() < expr2_->getValue();
    }
    else if (GT == compareType_)
    {
        return expr1_->getValue() > expr2_->getValue();
    }
    else if (LE == compareType_)
    {
        return expr1_->getValue() <= expr2_->getValue();
    }
    else if (GE == compareType_)
    {
        return expr1_->getValue() >= expr2_->getValue();
    }
    else if (NE == compareType_)
    {
        return expr1_->getValue() != expr2_->getValue();
    }
    else if (LIKE_KW == compareType_)
    {
        // Empty compares are always false
        if (expr2_->getValue().size() == 0)
        {
            return false;
        }
        regex perl(MySqlConstants::mySqlRegexToPerlRegex(expr2_->getValue()));
        return regex_match(expr1_->getValue(), perl);
    }
    else if (SOUNDS == compareType_)
    {
        return MySqlConstants::soundex(expr1_->getValue())
            == MySqlConstants::soundex(expr2_->getValue());
    }

    Logger::log(Logger::ERROR)
        << "Unknown comparison operator in ComparisonNode "
        << compareType_;
    assert(false);
    return true;
}


bool ComparisonNode::anyIsAlwaysTrue() const
{
    return ComparisonNode::isAlwaysTrue();
}


QueryRisk::EmptyPassword ComparisonNode::emptyPassword() const
{
    assert(
        0 == children_.size()
        || (1 == children_.size() && BETWEEN == compareType_)
    );

    // Only check for equality comparisons to password field
    if (
        EQ != compareType_
        || SensitiveNameChecker::get().isPasswordField(expr1_->getValue())
    )
    {
        return QueryRisk::PASSWORD_NOT_USED;
    }

    if (expr2_->getValue().empty())
    {
        return QueryRisk::PASSWORD_EMPTY;
    }
    return QueryRisk::PASSWORD_NOT_EMPTY;
}


bool ComparisonNode::resultsInValue() const
{
    // BETWEEN comparisons have an extra child to check
    if (BETWEEN == compareType_)
    {
        assert(children_.size() == 1);
        const ExpressionNode* const expr =
            polymorphic_downcast<const ExpressionNode*>(children_.at(0));
        if (!expr->resultsInValue())
        {
            return false;
        }
    }
    return expr1_->resultsInValue() && expr2_->resultsInValue();
}


string ComparisonNode::getValue() const
{
    assert(resultsInValue());
    /// @TODO(bskari|2012-07-28) Implement this
    return "";
}


void ComparisonNode::print(
    ostream& out,
    const int depth,
    const char indent
) const
{
    for (int i = 0; i < depth; ++i)
    {
        out << indent;
    }
    out << name_ << ':' << compareType_ << '\n';
    printChildren(out, depth + 1, indent);
}
