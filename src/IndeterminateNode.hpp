/*
 * SQLassie - database firewall
 * Copyright (C) 2012 Brandon Skari <brandon@skari.org>
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
 * Parse tree node that represents an expression that neither always true or
 * always false, but rather indeterminate. For example, any comparison that
 * uses fields is indeterminate.
 * @author Brandon Skari
 * @date October 12 2012
 */

#ifndef SRC_INDETERMINATENODE_HPP_
#define SRC_INDETERMINATENODE_HPP_

#include "AstNode.hpp"
#include "ExpressionNode.hpp"
#include "warnUnusedResult.h"

#include <string>


class IndeterminateNode : public ExpressionNode
{
public:
    /**
     * Default constructor.
     */
    IndeterminateNode();

    ~IndeterminateNode();

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
    IndeterminateNode(const IndeterminateNode& rhs);
    IndeterminateNode& operator=(const IndeterminateNode& rhs);
};
#endif  // SRC_INDETERMINATENODE_HPP_
