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

#include <boost/algorithm/string/predicate.hpp>
#include <boost/cast.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/regex.hpp>
#include <ctype.h>
#include <ostream>
#include <string>

using boost::lexical_cast;
using boost::iequals;
using boost::ilexicographical_compare;
using boost::polymorphic_downcast;
using boost::regex;
using boost::regex_replace;
using boost::regex_match;
using std::ostream;
using std::string;

static bool compareStrings(
    const int compareType,
    const string& s1,
    const string& s2
);
static bool compareValues(
    const int compareType,
    const string& s1,
    const string& s2
);
static bool isPasswordField(const ExpressionNode* const en);


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


bool ComparisonNode::isAlwaysTrueOrFalse() const
{
    if (BETWEEN == compareType_)
    {
        const ExpressionNode* const expr =
            polymorphic_downcast<const ExpressionNode*>(children_.at(0));
        return expr->resultsInValue()
            && expr1_->resultsInValue()
            && expr2_->resultsInValue();
    }
    else
    {
        // Both expressions have to be isAlwaysTrueOrFalse, and they both need
        // to result in the same thing
        if (
            expr1_->isAlwaysTrueOrFalse()
            && expr2_->isAlwaysTrueOrFalse()
        )
        {
            if (
                expr1_->resultsInValue()
                && expr2_->resultsInValue()
            )
            {
                return true;
            }
            if (
                expr1_->resultsInString()
                && expr2_->resultsInString()
            )
            {
                return true;
            }
        }
    }
    return false;
}


bool ComparisonNode::isAlwaysTrue() const
{
    assert(isAlwaysTrueOrFalse());
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
            expr->resultsInValue()
            && expr1_->resultsInValue()
            && expr2_->resultsInValue()
        )
        {
            return expr1_->getValue() <= expr->getValue()
                && expr->getValue() <= expr2_->getValue();
        }
        else
        {
            return false;
        }
    }

    assert(0 == children_.size() && "ComparisonNode should have no children");

    // Both either need to result in values or strings
    /// @TODO(bskari|2012-07-29) Handle things like (0 == '0')
    if (
        !(expr1_->resultsInValue() && expr2_->resultsInValue())
        && !(expr1_->resultsInString() && expr2_->resultsInString())
    )
    {
        return false;
    }

    if (expr1_->resultsInValue() && expr2_->resultsInValue())
    {
        return compareValues(
            compareType_,
            lexical_cast<string>(convertFloatOrHexString(expr1_->getValue())),
            lexical_cast<string>(convertFloatOrHexString(expr2_->getValue()))
        );
    }
    else
    {
        return compareStrings(
            compareType_,
            expr1_->getValue(),
            expr2_->getValue()
        );
    }
}


bool isPasswordField(const ExpressionNode* const en)
{
    return en->isField()
        && SensitiveNameChecker::isPasswordField(en->getValue());
}


QueryRisk::EmptyPassword ComparisonNode::emptyPassword() const
{
    assert(
        0 == children_.size()
        || (1 == children_.size() && BETWEEN == compareType_)
    );

    // Only check for equality comparisons to password field
    if (EQ != compareType_)
    {
        return QueryRisk::PASSWORD_NOT_USED;
    }
    if (!isPasswordField(expr1_) && !isPasswordField(expr2_))
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
    if (isAlwaysTrue())
    {
        return "1";
    }
    else
    {
        return "0";
    }
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


bool compareStrings(
    const int compareType,
    const string& s1,
    const string& s2
)
{
    switch (compareType)
    {
        // MySQL does case insensitive comparisons by default
        case EQ:
            return iequals(s1, s2);
        case NE:
            return !iequals(s1, s2);
        case LT:
            return ilexicographical_compare(s1, s2);
        case GT:
            return !ilexicographical_compare(s1, s2) && !iequals(s1, s2);
        case LE:
            return ilexicographical_compare(s1, s2) || iequals(s1, s2);
        case GE:
            return !ilexicographical_compare(s1, s2);
        case LIKE_KW:
            // Empty compares are always false
            if (s2.size() == 0)
            {
                return false;
            }
            else
            {
                regex perl(MySqlConstants::mySqlRegexToPerlRegex(s2));
                return regex_match(s1, perl);
            }
        case REGEXP:
            /// @TODO(bskari|2012-10-21) Empty regexps result in a MySQL error
            {
                regex posixExtended(s2, regex::extended);
                return regex_match(s1, posixExtended);
            }
        case SOUNDS:
            return MySqlConstants::soundex(s1) == MySqlConstants::soundex(s2);
        default:
            Logger::log(Logger::WARN) << "Unknown comparison operator "
                << compareType
                << " in ComparisonNode.cpp::compareStrings";
            assert(false);
            return false;
    }
}


bool compareValues(
    const int compareType,
    const string& s1,
    const string& s2
)
{
    switch (compareType)
    {
        case EQ:
            return s1 == s2;
        case LT:
            return s1 < s2;
        case GT:
            return s1 > s2;
        case LE:
            return s1 <= s2;
        case GE:
            return s1 >= s2;
        case NE:
            return s1 != s2;
        case LIKE_KW:
            // Empty compares are always false
            if (s2.size() == 0)
            {
                return false;
            }
            else
            {
                regex perl(MySqlConstants::mySqlRegexToPerlRegex(s2));
                return regex_match(s1, perl);
            }
        case SOUNDS:
            return MySqlConstants::soundex(s1) == MySqlConstants::soundex(s2);
        default:
            Logger::log(Logger::ERROR)
                << "Unknown comparison operator "
                << compareType
                << " in ComparisonNode.cpp::compareValues";
            assert(false);
            return false;
    }
}
