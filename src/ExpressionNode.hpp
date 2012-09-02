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
     * Determines if the conditionals always result in a true or false value.
     */
    ///@{
    virtual bool isAlwaysTrue() const WARN_UNUSED_RESULT = 0;
    bool isAlwaysFalse() const WARN_UNUSED_RESULT;
    virtual bool isAlwaysTrueOrFalse() const WARN_UNUSED_RESULT = 0;

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
     * Determines if this expression is reducible to a string.
     * ExpressionNode defines this as returning false. Most nodes won't need
     * to override this unless the default of false is inappropriate.
     */
    virtual bool resultsInString() const WARN_UNUSED_RESULT;

    /**
     * Determines if this expression is a field.
     * ExpressionNode defines this as returning false. Most nodes won't need
     * to override this unless the default of false is inappropriate.
     */
    virtual bool isField() const WARN_UNUSED_RESULT;

    /**
     * Returns the value of this node.
     */
    virtual std::string getValue() const WARN_UNUSED_RESULT = 0;

protected:
    typedef double SQL_FLOAT;
    /**
     * Converts a hex or floating point string to SQL_FLOAT.
     */
    static SQL_FLOAT convertFloatOrHexString(const std::string& str);

private:
    ExpressionNode(const ExpressionNode& rhs);
    ExpressionNode& operator=(const ExpressionNode& rhs);
};
#endif  // SRC_EXPRESSIONNODE_HPP_
