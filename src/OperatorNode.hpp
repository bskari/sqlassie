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

#ifndef SRC_OPERATORNODE_HPP_
#define SRC_OPERATOR_HPP_

#include "AstNode.hpp"
#include "warnUnusedResult.h"

#include <string>

/**
 * Parse tree node that holds a single operator, like '+' or '/'. Operators
 * are stored as the tokens as defined by the parser.
 * @author Brandon Skari
 * @date July 4 2012
 */

class OperatorNode : public AstNode
{
public:
    /**
     * Default constructor.
     * @param operatorToken The operator's token value, as defined by the parser.
     */
    OperatorNode(const int operatorToken);

    virtual ~OperatorNode();

    /**
     * Overridden from AstNode.
     */
    virtual AstNode* copy() const WARN_UNUSED_RESULT;

    /**
     * Gets the oeprator's token value.
     */
    int getOperator() const WARN_UNUSED_RESULT;

    /**
     * Overridden from AstNode.
     */
    virtual void print(
        std::ostream& out,
        const int depth,
        const char indent
    ) const;

private:
    const int operator_;

    OperatorNode(const OperatorNode& rhs);
    OperatorNode& operator=(const OperatorNode& rhs);
};
#endif  // SRC_OPERATORNODE_HPP_
