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

#ifndef SRC_ALWAYSSOMETHINGNODE_HPP_
#define SRC_ALWAYSSOMETHINGNODE_HPP_

#include "AstNode.hpp"
#include "ComparisonNode.hpp"
#include "warnUnusedResult.h"

/**
 * Parse tree node that represents an expression that is always either true or
 * false. This is used for expressions such as:
 * WHERE username LIKE '%'
 * or
 * WHERE username NOT LIKE '.'
 * @author Brandon Skari
 * @date December 12 2010
 */

class AlwaysSomethingNode : public ComparisonNode
{
public:
    /**
     * Default constructor.
     * @param always If this node is always true or always false.
     * @param compareType The comparison type token used, such as EQ or GE.
     */
    AlwaysSomethingNode(bool always, const int compareType);

    /**
     * Occasionally, I just want to insert an alwyas true node without
     * specifying the comparison type, e.g. expr IN (SELECT ...). I don't care
     * what the actual comparison is, I just want it to always be something.
     * @param always If this node is always true or always false.
     */
    AlwaysSomethingNode(bool always);

    virtual ~AlwaysSomethingNode();

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
     * Determines if any comparison is always true.
     * Overridden from ConditionalNode.
     */
    virtual bool anyIsAlwaysTrue() const WARN_UNUSED_RESULT;

private:
    const bool always_;

    AlwaysSomethingNode(const AlwaysSomethingNode& rhs);
    AlwaysSomethingNode& operator=(const AlwaysSomethingNode& rhs);
};
#endif  // SRC_ALWAYSSOMETHINGNODE_HPP_
