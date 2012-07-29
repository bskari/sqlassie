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
#include "BinaryOperatorNode.hpp"
#include "ExpressionNode.hpp"
#include "Logger.hpp"
#include "sqlParser.h"

#include <boost/lexical_cast.hpp>
#include <cassert>
#include <ostream>
#include <string>

using boost::lexical_cast;
using std::string;
using std::ostream;


BinaryOperatorNode::BinaryOperatorNode(
    const ExpressionNode* const expr1,
    const int operatorToken,
    const ExpressionNode* const expr2
)
    : ExpressionNode("BinaryOperator")
    , expr1_(expr1)
    , operator_(operatorToken)
    , expr2_(expr2)
{
}


BinaryOperatorNode::~BinaryOperatorNode()
{
}


AstNode* BinaryOperatorNode::copy() const
{
    BinaryOperatorNode* const temp = new BinaryOperatorNode(
        expr1_,
        operator_,
        expr2_
    );
    assert(children_.empty());
    return temp;
}


bool BinaryOperatorNode::isAlwaysTrue() const
{
    const string value(getValue());
    return "0" != value && "0.0" != value;
}


bool BinaryOperatorNode::anyIsAlwaysTrue() const
{
    return isAlwaysTrue();
}


QueryRisk::EmptyPassword BinaryOperatorNode::emptyPassword() const
{
    /// @TODO(bskari|2012-07-28) Do I need to do something else here?
    return QueryRisk::PASSWORD_NOT_USED;
}


int BinaryOperatorNode::getBinaryOperator() const
{
    return operator_;
}


bool BinaryOperatorNode::resultsInValue() const
{
    return expr1_->resultsInValue() && expr2_->resultsInValue();
}


string BinaryOperatorNode::getValue() const
{
    typedef double SQL_FLOAT;
    typedef int64_t SQL_INT;
    const SQL_FLOAT expr1 = lexical_cast<SQL_FLOAT>(expr1_->getValue());
    const SQL_FLOAT expr2 = lexical_cast<SQL_FLOAT>(expr2_->getValue());

    SQL_INT llExpr1, llExpr2;

    switch (operator_)
    {
    // Mathematical operators
    case PLUS:
        return lexical_cast<string>(expr1 + expr2);
    case MINUS:
        return lexical_cast<string>(expr1 - expr2);
    case STAR:
        return lexical_cast<string>(expr1 * expr2);
    case SLASH:
        return lexical_cast<string>(expr1 / expr2);
    case INTEGER_DIVIDE:
        // MySQL rounds the parameters if they're floating point
        llExpr1 = llround(expr1);
        llExpr2 = llround(expr2);
        return lexical_cast<string>(llExpr1 / llExpr2);
    case REM:
        return lexical_cast<string>(fmod(expr1, expr2));
    // Bitwise manipulation operators
    case BITAND:
        // MySQL rounds floats when used with binary operators
        llExpr1 = static_cast<SQL_INT>(round(expr1));
        llExpr2 = static_cast<SQL_INT>(round(expr2));
        return lexical_cast<string>(llExpr1 & llExpr2);
    case BITOR:
        // MySQL rounds floats when used with binary operators
        llExpr1 = static_cast<SQL_INT>(round(expr1));
        llExpr2 = static_cast<SQL_INT>(round(expr2));
        return lexical_cast<string>(llExpr1 | llExpr2);
    case LSHIFT:
        llExpr1 = static_cast<SQL_INT>(round(expr1));
        llExpr2 = static_cast<SQL_INT>(round(expr2));
        return lexical_cast<string>(llExpr1 << llExpr2);
    case RSHIFT:
        llExpr1 = static_cast<SQL_INT>(round(expr1));
        llExpr2 = static_cast<SQL_INT>(round(expr2));
        return lexical_cast<string>(llExpr1 >> llExpr2);
    default:
        Logger::log(Logger::ERROR)
            << "Unknown operator in ExpressionNode: '"
            << operator_
            << '\'';
        assert(false);
        return "0.0";
    }
}


void BinaryOperatorNode::print(
    ostream& out,
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
    expr1_->print(out, depth + 1, indent);
    expr2_->print(out, depth + 1, indent);
}
