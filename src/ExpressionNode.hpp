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

#ifndef SRC_EXPRESSIONNODE_HPP_
#define SRC_EXPRESSIONNODE_HPP_

#include "ConditionalNode.hpp"
#include "QueryRisk.hpp"
#include "warnUnusedResult.h"

#include <string>

/**
 * Parse tree node that represents an expression.
 * @author Brandon Skari
 * @date December 10 2010
 */

class ExpressionNode : public ConditionalNode
{
public:
    /**
     * Default constructor that uses its children to handle getValue().
     */
    ExpressionNode();

    /**
     * Constructor for terminal nodes, such as strings, numbers, or identifiers.
     * @param expression The string or number.
     * @param isIdentifier If this string is an identifier.
     */
    ExpressionNode(const std::string& expression, bool isIdentifier);

    virtual ~ExpressionNode();

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
     * Gets the value of this expression.
     */
    std::string getValue() const WARN_UNUSED_RESULT;

    /**
     * Returns true if this is an identifier.
     */
    bool isIdentifier() const WARN_UNUSED_RESULT;

    /**
     * Returns true if this is a number literal.
     */
    bool isNumber() const WARN_UNUSED_RESULT;

    /**
     * Overridden from AstNode.
     */
    virtual void print(
        std::ostream& out,
        const int depth,
        const char indent
    ) const;

    /**
     * Determines if the string represents a decimal number.
     */
    static bool isNumber(const std::string& str);

private:
    const std::string expression_;
    const bool number_;
    const bool identifier_;
    const bool quotedString_;

    ExpressionNode(const ExpressionNode& rhs);
    ExpressionNode& operator=(const ExpressionNode& rhs);
};
#endif  // SRC_EXPRESSIONNODE_HPP_
