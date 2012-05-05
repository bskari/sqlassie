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
#include "ExpressionNode.hpp"
#include "Logger.hpp"
#include "nullptr.hpp"

#include <boost/cstdint.hpp>
#include <boost/lexical_cast.hpp>
#include <cassert>
#include <cmath>
#include <ostream>
#include <string>

using std::string;
using boost::lexical_cast;
using boost::bad_lexical_cast;


ExpressionNode::ExpressionNode() :
    ConditionalNode("Expression"),
    expression_(),
    number_(false),
    identifier_(false),
    quotedString_(false)
{
}


ExpressionNode::ExpressionNode(const std::string& str, bool isIdentifier_) :
    ConditionalNode("Expression"),
    expression_(str),
    number_(isNumber(str)),
    identifier_(isIdentifier_),
    quotedString_(!identifier_ && !number_)
{
    assert(
        !(number_ && identifier_)
        && "ExpressionNode constructor was given a number but claims to be an"
        && "identifier"
    );
}


ExpressionNode::~ExpressionNode()
{
}


AstNode* ExpressionNode::copy() const
{
    ExpressionNode* const temp = new ExpressionNode();
    AstNode::addCopyOfChildren(temp);
    return temp;
}


bool ExpressionNode::isAlwaysTrue() const
{
    const string value(getValue());
    if (isNumber(value))
    {
        const double d = lexical_cast<double>(value);
        // Non-zero's are true
        if (d > -0.000000001 && d < 0.000000001)
        {
            return false;
        }
        else
        {
            return true;
        }
    }

    // Strings are considered false
    return false;
}


bool ExpressionNode::anyIsAlwaysTrue() const
{
    return isAlwaysTrue();
}


string ExpressionNode::getValue() const
{
    // Expressions can resolve to either just a simple expression, or 2
    // expressions with an operator
    if (number_ || identifier_ || quotedString_)
    {
        return expression_;
    }

    assert(
        3 == children_.size()
        && "Expression nodes should either have a simple expression or two"
        && "simple expressions with an operator for children"
    );

    const ExpressionNode* expr1 = dynamic_cast<const ExpressionNode*>(
        children_.at(0)
    );
    const ExpressionNode* expr2 = dynamic_cast<const ExpressionNode*>(
        children_.at(2)
    );
    assert(
        nullptr != expr1
        && nullptr != expr2
        && "ExpressionNode should only have ExpressionNode children"
    );

    // MySQL lets you use quoted strings as integers... but if someone is
    // computing, say, 1 + 'foo', it returns the only integer. If both are
    // strings, then it returns 0.
    double child1 = 0, child2 = 0;
    try
    {
        if (isNumber(expr1->getValue()))
        {
            child1 = lexical_cast<double>(expr1->getValue());
        }
        if (isNumber(expr2->getValue()))
        {
            child2 = lexical_cast<double>(expr2->getValue());
        }
    }
    catch (bad_lexical_cast&) {}

    const string& oper = children_.at(1)->getName();
    if ("+" == oper)
    {
        return lexical_cast<string>(child1 + child2);
    }
    else if ("-" == oper)
    {
        return lexical_cast<string>(child1 - child2);
    }
    else if ("*" == oper)
    {
        return lexical_cast<string>(child1 * child2);
    }
    else if ("/" == oper)
    {
        return lexical_cast<string>(child1 / child2);
    }
    else if ("DIV" == oper)
    {
        // MySQL rounds the parameters if they're floating point
        int64_t llChild1 = llround(child1);
        int64_t llChild2 = llround(child1);
        return lexical_cast<string>(llChild1 / llChild2);
    }
    else if ("MOD" == oper)
    {
        return lexical_cast<string>(fmod(child1, child2));
    }
    else if ("&" == oper)
    {
        // MySQL rounds floats when used with binary operators
        int c1 = static_cast<int>(round(child1));
        int c2 = static_cast<int>(round(child2));
        return lexical_cast<string>(c1 & c2);
    }
    else if ("|" == oper)
    {
        // MySQL rounds floats when used with binary operators
        int c1 = static_cast<int>(round(child1));
        int c2 = static_cast<int>(round(child2));
        return lexical_cast<string>(c1 | c2);
    }
    else if ("<<" == oper)
    {
        int c1 = static_cast<int>(round(child1));
        int c2 = static_cast<int>(round(child2));
        return lexical_cast<string>(c1 << c2);
    }
    else if (">>" == oper)
    {
        int c1 = static_cast<int>(round(child1));
        int c2 = static_cast<int>(round(child2));
        return lexical_cast<string>(c1 >> c2);
    }
    else
    {
        Logger::log(Logger::ERROR) << "Unknown operator in ExpressionNode: '" << oper << '\'';
        assert(false);
        return "0.0";
    }
}


bool ExpressionNode::isIdentifier() const
{
    return identifier_;
}


bool ExpressionNode::isNumber() const
{
    return number_;
}


QueryRisk::EmptyPassword ExpressionNode::emptyPassword() const
{
    return QueryRisk::PASSWORD_NOT_USED;
}


bool ExpressionNode::isNumber(const std::string& str)
{
    // This method has been optimized because SQLassie was spending a lot of
    // time in this method. Originally, this method would take str by value and
    // would always trim it, and would use a regular expression to determine if
    // str was a number. By sending str by reference and checking manually,
    // SQLassie's runtime is decreased by about 10%.

    if (0 == str.length())
    {
        return false;
    }

    const string::const_iterator end(str.end());
    string::const_iterator i(str.begin());
    bool digit = false;

    // Skip white space, it's faster than trimming
    while (end != i && (' ' == *i || '\t' == *i))
    {
        ++i;
    }

    // The first character can be a unary +, -, or ~
    if ('-' == *i || '~' == *i || '+' == *i)
    {
        ++i;
    }

    // Skip digits
    for (; i != end; ++i)
    {
        if (*i < '0' || *i > '9')
        {
            break;
        }
        digit = true;
    }

    // If there were only digits, then it's a number
    if (end == i)
    {
        return true;
    }

    // Check for floating point numbers
    if ('.' == *i)
    {
        ++i; // Skip .
        for (; i != end; ++i)
        {
            if (*i < '0' || *i > '9')
            {
                break;
            }
            digit = true;
        }
    }

    // Skip white space, it's faster than trimming
    while (end != i && (' ' == *i || '\t' == *i))
    {
        ++i;
    }

    return end == i && digit;
}


void ExpressionNode::print(
    std::ostream& out,
    const int depth,
    const char indent
) const
{
    for (int i = 0; i < depth; ++i)
    {
        out << indent;
    }
    out << name_ << ':' << expression_ << '\n';
    printChildren(out, depth + 1, indent);
}
