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

/**
 * Parse tree node that represents a function call.
 * @author Brandon Skari
 * @date July 28 2012
 */

#ifndef SRC_FUNCTIONNODE_HPP_
#define SRC_FUNCTIONNODE_HPP_

#include "AstNode.hpp"
#include "ExpressionNode.hpp"
#include "warnUnusedResult.h"

#include <iosfwd>
#include <string>


class FunctionNode : public ExpressionNode
{
public:
    /**
     * Default constructor.
     */
    explicit FunctionNode(const std::string& functionName);

    ~FunctionNode();

    /**
     * Overridden from AstNode.
     */
    AstNode* copy() const WARN_UNUSED_RESULT;

    /**
     * Determines if the conditionals result in always true or always false.
     * Overridden from ExpressionNode.
     */
    bool isAlwaysTrueOrFalse() const WARN_UNUSED_RESULT;

    /**
     * Determines if the conditionals are always true.
     * Overridden from ExpressionNode.
     */
    bool isAlwaysTrue() const WARN_UNUSED_RESULT;

    /**
     * Determines if this expression is reducible to a value, either a string
     * or a number.
     */
    bool resultsInValue() const WARN_UNUSED_RESULT;

    /**
     * Returns the value of this node.
     */
    std::string getValue() const WARN_UNUSED_RESULT;

    /**
     * Overridden from AstNode.
     */
    void print(
        std::ostream& out,
        const int depth,
        const char indent
    ) const;

private:
    const std::string functionName_;

    FunctionNode(const FunctionNode&);
    FunctionNode& operator=(const FunctionNode);
};
#endif  // SRC_FUNCTIONNODE_HPP_
