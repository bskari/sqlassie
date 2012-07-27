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

using boost::polymorphic_downcast;
using boost::regex;
using boost::regex_replace;
using boost::regex_match;
using std::ostream;


ComparisonNode::ComparisonNode(const int compareType) :
    ConditionalNode("Comparison"),
    compareType_(compareType)
{
}


ComparisonNode::~ComparisonNode()
{
}


AstNode* ComparisonNode::copy() const
{
    ComparisonNode* const temp = new ComparisonNode(compareType_);
    AstNode::addCopyOfChildren(temp);
    return temp;
}


bool ComparisonNode::isAlwaysTrue() const
{
    if (BETWEEN == compareType_)
    {
        assert(3 == children_.size() && "BETWEEN operators should have 3 children");
        // This is logically equivalent to
        // (min[child1] <= expr[child0] AND expr[child0] <= max[child2])
        const ExpressionNode* const expr = polymorphic_downcast<const ExpressionNode*>(
            children_.at(0)
        );
        const ExpressionNode* const minExpr = polymorphic_downcast<const ExpressionNode*>(
            children_.at(1)
        );
        const ExpressionNode* const maxExpr = polymorphic_downcast<const ExpressionNode*>(
            children_.at(2)
        );

        // We only care about numbers; anything else (like identifiers) is
        // assumed to not always be true
        if (
            ExpressionNode::isNumber(minExpr->getValue())
            && ExpressionNode::isNumber(minExpr->getValue())
            && ExpressionNode::isNumber(minExpr->getValue())
        )
        {
            std::cout << minExpr->getValue() << " <= " << expr->getValue() << " <= " << maxExpr->getValue() << std::endl;
            return minExpr->getValue() <= expr->getValue()
                && expr->getValue() <= maxExpr->getValue();
        }
    }

    assert(2 == children_.size() && "ComparisonNode should have 2 children");

    const ExpressionNode* const expr1 = polymorphic_downcast<const ExpressionNode*>(
        children_.at(0)
    );
    const ExpressionNode* const expr2 = polymorphic_downcast<const ExpressionNode*>(
        children_.at(1)
    );

    // Fields may or may not compare correctly, so assume it's legitimate
    if (expr1->isIdentifier() || expr2->isIdentifier())
    {
        return false;
    }

    if (EQ == compareType_)
    {
        return expr1->getValue() == expr2->getValue();
    }
    else if (LT == compareType_)
    {
        return expr1->getValue() < expr2->getValue();
    }
    else if (GT == compareType_)
    {
        return expr1->getValue() > expr2->getValue();
    }
    else if (LE == compareType_)
    {
        return expr1->getValue() <= expr2->getValue();
    }
    else if (GE == compareType_)
    {
        return expr1->getValue() >= expr2->getValue();
    }
    else if (NE == compareType_)
    {
        return expr1->getValue() != expr2->getValue();
    }
    else if (LIKE_KW == compareType_)
    {
        // Empty compares are always false
        if (expr2->getValue().size() == 0)
        {
            return false;
        }
        regex perl(MySqlConstants::mySqlRegexToPerlRegex(expr2->getValue()));
        return regex_match(expr1->getValue(), perl);
    }
    else if (SOUNDS == compareType_)
    {
        return MySqlConstants::soundex(expr1->getValue())
            == MySqlConstants::soundex(expr2->getValue());
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
    assert(2 == children_.size() && "ComparisonNode should have 2 children");

    const ExpressionNode* const expr1 = polymorphic_downcast<const ExpressionNode*>(
        children_.at(0)
    );
    const ExpressionNode* const expr2 = polymorphic_downcast<const ExpressionNode*>(
        children_.at(1)
    );

    // Only check for equality comparisons to password field
    if (
        EQ != compareType_
        || SensitiveNameChecker::get().isPasswordField(expr1->getValue())
    )
    {
        return QueryRisk::PASSWORD_NOT_USED;
    }

    if (expr2->getValue().empty())
    {
        return QueryRisk::PASSWORD_EMPTY;
    }
    return QueryRisk::PASSWORD_NOT_EMPTY;
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
