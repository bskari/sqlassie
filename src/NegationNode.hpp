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

#ifndef SRC_NEGATIONNODE_HPP_
#define SRC_NEGATIONNODE_HPP_

#include "ExpressionNode.hpp"
#include "QueryRisk.hpp"
#include "warnUnusedResult.h"

#include <iosfwd>
#include <string>

/**
 * Parse tree node that represents a negation of a conditional node.
 * @author Brandon Skari
 * @date January 2 2012
 */

class NegationNode : public ExpressionNode
{
public:
    /**
     * Default constructor.
     */
    explicit NegationNode(const ExpressionNode* const expression);

    ~NegationNode();

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
     * Determines if the comparison is always true.
     * Overridden from ComparisonNode.
     */
    bool isAlwaysTrue() const WARN_UNUSED_RESULT;

    /**
     * Determines if the comparison is always true.
     * Overridden from ComparisonNode.
     */
    bool anyIsAlwaysTrue() const WARN_UNUSED_RESULT;

    /**
     * Determines if the password is empty.
     */
    QueryRisk::EmptyPassword emptyPassword() const WARN_UNUSED_RESULT;

    /**
     * Determines if there is an empty password.
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
    void print(
        std::ostream& out,
        const int depth,
        const char indent
    ) const;

private:
    const ExpressionNode* expression_;

    NegationNode(const NegationNode&);
    NegationNode& operator=(NegationNode&);
};
#endif  // SRC_NEGATIONNODE_HPP_
