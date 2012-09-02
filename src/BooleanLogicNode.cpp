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
#include "BooleanLogicNode.hpp"
#include "Logger.hpp"
#include "QueryRisk.hpp"
#include "sqlParser.h"

#include <cassert>
#include <ostream>
#include <string>

using std::ostream;
using std::string;


BooleanLogicNode::BooleanLogicNode(
    const ExpressionNode* const expr1,
    const int logicalOperator,
    const ExpressionNode* const expr2
)
    : ExpressionNode("BooleanLogic")
    , expr1_(expr1)
    , logicalOperator_(logicalOperator)
    , expr2_(expr2)
{
}


BooleanLogicNode::~BooleanLogicNode()
{
    delete expr1_;
    delete expr2_;
}


AstNode* BooleanLogicNode::copy() const
{
    BooleanLogicNode* const temp = new BooleanLogicNode(
        expr1_,
        logicalOperator_,
        expr2_
    );
    AstNode::addCopyOfChildren(temp);
    return temp;
}


bool BooleanLogicNode::isAlwaysTrueOrFalse() const
{
    return expr1_->isAlwaysTrueOrFalse() && expr2_->isAlwaysTrueOrFalse();
}


bool BooleanLogicNode::isAlwaysTrue() const
{
    switch (logicalOperator_)
    {
    case AND:
        return expr1_->isAlwaysTrue() && expr2_->isAlwaysTrue();
    case OR:
        return expr1_->isAlwaysTrue() || expr2_->isAlwaysTrue();
    case XOR:
        return (
            (expr1_->isAlwaysTrue() && !expr2_->isAlwaysTrue())
            || (!expr1_->isAlwaysTrue() && expr2_->isAlwaysTrue())
        );
    default:
        Logger::log(Logger::ERROR)
            << "Unknown operator in BooleanLogicNode: '"
            << logicalOperator_
            << '\'';
        assert(false);
        return false;
    }
}


QueryRisk::EmptyPassword BooleanLogicNode::emptyPassword() const
{
    // Here, we need to examine both nodes to examine the password risk.
    // If one has an empty password, return that, because that's very risky.
    // If one has a nonempty password, return that, because the other is benign.
    // If neither are using passwords, return that.
    if (
        QueryRisk::PASSWORD_EMPTY == expr1_->emptyPassword()
        || QueryRisk::PASSWORD_EMPTY == expr2_->emptyPassword()
    )
    {
        return QueryRisk::PASSWORD_EMPTY;
    }

    if (
        QueryRisk::PASSWORD_NOT_EMPTY == expr1_->emptyPassword()
        || QueryRisk::PASSWORD_NOT_EMPTY == expr2_->emptyPassword()
    )
    {
        return QueryRisk::PASSWORD_NOT_EMPTY;
    }

    return QueryRisk::PASSWORD_NOT_USED;
}


bool BooleanLogicNode::resultsInValue() const
{
    return true;
}


string BooleanLogicNode::getValue() const
{
    /// @TODO(bskari|2012-07-28) Do something!
    return "";
}


void BooleanLogicNode::print(
    ostream& out,
    const int depth,
    const char indent
) const
{
    for (int i = 0; i < depth; ++i)
    {
        out << indent;
    }
    out << name_ << ':' << logicalOperator_ << '\n';
    printChildren(out, depth + 1, indent);
}
