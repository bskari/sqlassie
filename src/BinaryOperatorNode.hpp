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

#ifndef SRC_BINARYOPERATORNODE_HPP_
#define SRC_BINARYOPERATORNODE_HPP_

#include "AstNode.hpp"
#include "ExpressionNode.hpp"
#include "warnUnusedResult.h"

#include <string>

/**
 * Parse tree node that holds a binary operator, like '+' or '/', and two
 * expressions that the operator operatos on. The operator is stored as the
 * token value as defined by the parser.
 * @author Brandon Skari
 * @date July 4 2012
 */

class BinaryOperatorNode : public ExpressionNode
{
public:
    /**
     * Default constructor.
     * @param operatorToken The operator's token value, as defined by the parser.
     */
    BinaryOperatorNode(
        const ExpressionNode* const expr1,
        const int operatorToken,
        const ExpressionNode* const expr2
    );

    virtual ~BinaryOperatorNode();

    /**
     * Overridden from AstNode.
     */
    virtual AstNode* copy() const WARN_UNUSED_RESULT;

    /**
     * Determines if the conditionals are always true.
     * Overridden from ExpressionNode.
     */
    bool isAlwaysTrue() const WARN_UNUSED_RESULT;

    /**
     * Determines if any of this node's children are always true.
     * Overridden from ExpressionNode.
     */
    bool anyIsAlwaysTrue() const WARN_UNUSED_RESULT;

    /**
     * Determines if there is an empty password.
     * Overridden from ExpressionNode.
     */
    QueryRisk::EmptyPassword emptyPassword() const WARN_UNUSED_RESULT;

    /**
     * Gets the operator's token value.
     */
    int getBinaryOperator() const WARN_UNUSED_RESULT;

    /**
     * Determines if the there is an empty password.
     * Overridden from ExpressionNode.
     */
    bool resultsInValue() const WARN_UNUSED_RESULT;

    /**
     * Gets the value of this expression.
     * Overridden from ExpressionNode.
     */
    std::string getValue() const WARN_UNUSED_RESULT;

    /**
     * Overridden from AstNode.
     */
    virtual void print(
        std::ostream& out,
        const int depth,
        const char indent
    ) const;

private:
    const ExpressionNode* const expr1_;
    const int operator_;
    const ExpressionNode* const expr2_;

    BinaryOperatorNode(const BinaryOperatorNode& rhs);
    BinaryOperatorNode& operator=(const BinaryOperatorNode& rhs);
};
#endif  // SRC_BINARYOPERATORNODE_HPP_
