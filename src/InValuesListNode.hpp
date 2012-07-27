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

#ifndef SRC_INVALUESLISTNODE_HPP_
#define SRC_INVALUESLISTNODE_HPP_

#include "AstNode.hpp"
#include "ConditionalNode.hpp"
#include "ExpressionNode.hpp"
#include "warnUnusedResult.h"

#include <string>

/**
 * Parse tree node that represents MySQL commands like this:
 * someExpression IN ('a', 'b', 'c').
 * @author Brandon Skari
 * @date December 9 2010
 */

class InValuesListNode : public ConditionalNode
{
public:
    /**
     * Default constructor.
     * @param in Whether this represents an IN or a NOT IN list.
     * @param expression The expression that's being checked to see if it's in
     * the list.
     */
    InValuesListNode(const ExpressionNode* expression);

    virtual ~InValuesListNode();

    /**
     * Overridden from AstNode.
     */
    virtual AstNode* copy() const WARN_UNUSED_RESULT;

    /**
     * Determines if the conditionals are always true.
     * Overridden from ConditionalNode.
     */
    virtual bool isAlwaysTrue() const WARN_UNUSED_RESULT;

    /**
     * Determines if any of this node's children are always true.
     * Overridden from ConditionalNode.
     */
    virtual bool anyIsAlwaysTrue() const WARN_UNUSED_RESULT;

    /**
     * Determines if the password is empty.
     * Overridden from ConditionalNode.
     */
    virtual QueryRisk::EmptyPassword emptyPassword() const WARN_UNUSED_RESULT;

    /**
     * Overridden from AstNode.
     */
    virtual void print(
        std::ostream& out,
        const int depth,
        const char indent
    ) const;

protected:
    const ExpressionNode* const expression_;

private:
    InValuesListNode(const InValuesListNode& rhs);
    InValuesListNode& operator=(const InValuesListNode& rhs);
};
#endif  // SRC_INVALUESLISTNODE_HPP_
