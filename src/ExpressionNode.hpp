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

/**
 * Parse tree node that represents an expression.
 * @author Brandon Skari
 * @date December 10 2010
 */

#ifndef SRC_EXPRESSIONNODE_HPP_
#define SRC_EXPRESSIONNODE_HPP_

#include "AstNode.hpp"
#include "QueryRisk.hpp"
#include "warnUnusedResult.h"

#include <string>


class ExpressionNode : public AstNode
{
public:
    explicit ExpressionNode(const std::string& name);
    virtual ~ExpressionNode();

    /**
     * Determines if the conditionals are always true.
     */
    virtual bool isAlwaysTrue() const WARN_UNUSED_RESULT = 0;

    /**
     * Determines if any of this node's children are always true.
     */
    virtual bool anyIsAlwaysTrue() const WARN_UNUSED_RESULT = 0;

    /**
     * Determines if there is an empty password.
     */
    virtual QueryRisk::EmptyPassword emptyPassword()
        const WARN_UNUSED_RESULT = 0;

    /**
     * Determines if this expression is reducible to a number.
     * Example:
     * 1 + 1 => true
     * age + 1 => false
     */
    virtual bool resultsInValue() const WARN_UNUSED_RESULT = 0;

    /**
     * Returns the value of this node.
     */
    virtual std::string getValue() const WARN_UNUSED_RESULT = 0;

private:
    ExpressionNode(const ExpressionNode& rhs);
    ExpressionNode& operator=(const ExpressionNode& rhs);
};
#endif  // SRC_EXPRESSIONNODE_HPP_
