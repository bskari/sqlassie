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

#include "assertCast.hpp"
#include "AstNode.hpp"
#include "ConditionalListNode.hpp"
#include "ConditionalNode.hpp"
#include "Logger.hpp"
#include "nullptr.hpp"

#include <string>
#include <cassert>
using std::string;
using std::ostream;


ConditionalListNode::ConditionalListNode(const char logicalOp) :
    ConditionalNode("ConditionalList"),
    logicalOp_(logicalOp)
{
}


ConditionalListNode::~ConditionalListNode()
{
}


AstNode* ConditionalListNode::copy() const
{
    ConditionalListNode* const temp = new ConditionalListNode(logicalOp_);
    AstNode::addCopyOfChildren(temp);
    return temp;
}


bool ConditionalListNode::isAlwaysTrue() const
{
    assert(2 == children_.size() &&
        "ConditionalList should have 2 children");

    const ConditionalNode* cond1 = assert_cast<const ConditionalNode*>(
        children_.at(0)
    );
    const ConditionalNode* cond2 = assert_cast<const ConditionalNode*>(
        children_.at(1)
    );

    if ('&' == logicalOp_)
    {
        return cond1->isAlwaysTrue() && cond2->isAlwaysTrue();
    }
    else if ('|' == logicalOp_)
    {
        return cond1->isAlwaysTrue() || cond2->isAlwaysTrue();
    }
    else if ('^' == logicalOp_)
    {
        return cond1->isAlwaysTrue() != cond2->isAlwaysTrue();
    }
    else
    {
        Logger::log(Logger::ERROR)
            << "Unexpected binary logical operator in conditionalList "
            << logicalOp_;
        assert(false);
        return false;
    }
}


bool ConditionalListNode::anyIsAlwaysTrue() const
{
    assert(2 == children_.size() &&
        "ConditionalList should have 2 children");

    const ConditionalNode* cond1 = assert_cast<const ConditionalNode*>(
        children_.at(0)
    );
    const ConditionalNode* cond2 = assert_cast<const ConditionalNode*>(
        children_.at(1)
    );

    return cond1->anyIsAlwaysTrue() || cond2->anyIsAlwaysTrue();
}


QueryRisk::EmptyPassword ConditionalListNode::emptyPassword() const
{
    assert(2 == children_.size() &&
        "ConditionalList should have 2 children");

    const ConditionalNode* cond1 = assert_cast<const ConditionalNode*>(
        children_.at(0)
    );
    const ConditionalNode* cond2 = assert_cast<const ConditionalNode*>(
        children_.at(1)
    );

    QueryRisk::EmptyPassword empty1 = cond1->emptyPassword();
    QueryRisk::EmptyPassword empty2 = cond2->emptyPassword();

    if (QueryRisk::PASSWORD_EMPTY == empty1
        || QueryRisk::PASSWORD_EMPTY == empty2)
    {
        return QueryRisk::PASSWORD_EMPTY;
    }
    else if (QueryRisk::PASSWORD_NOT_EMPTY == empty1
        || QueryRisk::PASSWORD_NOT_EMPTY == empty2)
    {
        return QueryRisk::PASSWORD_NOT_EMPTY;
    }
    else
    {
        return QueryRisk::PASSWORD_NOT_USED;
    }
}


void ConditionalListNode::print(
    ostream& out,
    const int depth,
    const char indent
) const
{
    for (int i = 0; i < depth; ++i)
    {
        out << indent;
    }
    out << name_ << ':' << logicalOp_;
    printChildren(out, depth + 1, indent);
}
