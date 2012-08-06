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

#ifndef SRC_COMPARISONNODE_HPP_
#define SRC_COMPARISONNODE_HPP_

#include "ExpressionNode.hpp"
#include "QueryRisk.hpp"
#include "warnUnusedResult.h"

#include <iosfwd>

/**
 * Parse tree node that represents a comparison between two expressions. The
 * comparisons can be things like equality, greater than, like, or sounds like.
 * @author Brandon Skari
 * @date December 9 2010
 */

class ComparisonNode : public ExpressionNode
{
public:
    /**
     * Default constructor.
     * @param compareType The type of comparison being used.
     */
    ComparisonNode(
        const ExpressionNode* const expr1,
        const int compareType,
        const ExpressionNode* const expr2
    );

    ~ComparisonNode();

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
     * Overridden from ExpressionNode.
     */
    bool isAlwaysTrue() const WARN_UNUSED_RESULT;

    /**
     * Determines if the comparison is always true.
     * Overridden from ExpressionNode.
     */
    bool anyIsAlwaysTrue() const WARN_UNUSED_RESULT;

    /**
     * Determines if the password is empty.
     */
    QueryRisk::EmptyPassword emptyPassword() const WARN_UNUSED_RESULT;

    /**
     * Determines if this node ultimately results in a value.
     * Overridden from ExpressionNode.
     */
    bool resultsInValue() const WARN_UNUSED_RESULT;

    /**
     * Returns the value of this node.
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
    const ExpressionNode* const expr1_;
    int compareType_;
    const ExpressionNode* const expr2_;

    ComparisonNode(const ComparisonNode& rhs);
    ComparisonNode& operator=(ComparisonNode& rhs);
};
#endif  // SRC_COMPARISONNODE_HPP_
