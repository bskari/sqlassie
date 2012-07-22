/*
 * SQLassie - database firewall
 * Copyright (C) 2012 Brandon Skari <brandon.skari@gmail.com>
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

#ifndef SRC_BOOLEANLOGICNODE_HPP_
#define SRC_BOOLEANLOGICNODE_HPP_

#include "ConditionalNode.hpp"
#include "QueryRisk.hpp"
#include "warnUnusedResult.h"

#include <iosfwd>

/**
 * Parse tree node that represents an expression.
 * @author Brandon Skari
 * @date December 10 2010
 */

class BooleanLogicNode : public ConditionalNode
{
public:
    /**
     * Default constructor.
     * @param logicalOp The logical binary operator type.
     */
    BooleanLogicNode(const int logicalOperator);

    virtual ~BooleanLogicNode();

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
     * Determines if the any of this node's children are always true.
     * Overridden from ConditionalNode.
     */
    virtual bool anyIsAlwaysTrue() const WARN_UNUSED_RESULT;

    /**
     * Determines if the there is an empty password.
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

private:
    const int logicalOperator_;

    BooleanLogicNode(const BooleanLogicNode& rhs);
    BooleanLogicNode& operator=(const BooleanLogicNode& rhs);
};
#endif  // SRC_BOOLEANLOGICNODE_HPP_
