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
#include "OperatorNode.hpp"
#include "QueryRisk.hpp"
#include "sqlParser.h"

#include <boost/cast.hpp>
#include <boost/cstdint.hpp>
#include <boost/lexical_cast.hpp>
#include <cassert>
#include <ostream>

using boost::bad_lexical_cast;
using boost::lexical_cast;
using boost::polymorphic_downcast;


BooleanLogicNode::BooleanLogicNode(const int logicalOperator) :
    ConditionalNode("BooleanLogic"),
    logicalOperator_(logicalOperator)
{
}


BooleanLogicNode::~BooleanLogicNode()
{
}


AstNode* BooleanLogicNode::copy() const
{
    BooleanLogicNode* const temp = new BooleanLogicNode(logicalOperator_);
    AstNode::addCopyOfChildren(temp);
    return temp;
}


bool BooleanLogicNode::isAlwaysTrue() const
{
    assert(2 == children_.size() && "BooleanLogicNode should have 2 children");

    const ConditionalNode* const c1 =
        polymorphic_downcast<const ConditionalNode*>(children_.at(0));
    const ConditionalNode* const c2 =
        polymorphic_downcast<const ConditionalNode*>(children_.at(1));

    switch (logicalOperator_)
    {
    case AND:
        return c1->isAlwaysTrue() && c2->isAlwaysTrue();
    case OR:
        return c1->isAlwaysTrue() || c2->isAlwaysTrue();
    case XOR:
        return (
            (c1->isAlwaysTrue() && !c2->isAlwaysTrue())
            || (!c1->isAlwaysTrue() && c2->isAlwaysTrue())
        );
    default:
        Logger::log(Logger::ERROR)
            << "Unknown operator in BooleanLogicNode: '"
            << '\'';
        assert(false);
        return false;
    }
}


bool BooleanLogicNode::anyIsAlwaysTrue() const
{
    return isAlwaysTrue();
}


QueryRisk::EmptyPassword BooleanLogicNode::emptyPassword() const
{
    assert(2 == children_.size() && "BooleanLogicNode should have 2 children");

    const ConditionalNode* const c1 =
        polymorphic_downcast<const ConditionalNode*>(children_.at(0));
    const ConditionalNode* const c2 =
        polymorphic_downcast<const ConditionalNode*>(children_.at(1));

    // Here, we need to examine both nodes to examine the password risk.
    // If one has an empty password, return that, because that's very risky.
    // If one has a nonempty password, return that, because the other is benign.
    // If neither are using passwords, return that.
    if (
        QueryRisk::PASSWORD_EMPTY == c1->emptyPassword()
        || QueryRisk::PASSWORD_EMPTY == c2->emptyPassword()
    )
    {
        return QueryRisk::PASSWORD_EMPTY;
    }

    if (
        QueryRisk::PASSWORD_NOT_EMPTY == c1->emptyPassword()
        || QueryRisk::PASSWORD_NOT_EMPTY == c2->emptyPassword()
    )
    {
        return QueryRisk::PASSWORD_NOT_EMPTY;
    }

    return QueryRisk::PASSWORD_NOT_USED;
}

void BooleanLogicNode::print(
    std::ostream& out,
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
