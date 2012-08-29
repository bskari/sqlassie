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
 * Parse tree node that represents either a number, a string, or an identiifer.
 * @author Brandon Skari
 * @date July 27 2012
 */

#ifndef SRC_TERMINALNODE_HPP_
#define SRC_TERMINALNODE_HPP_

#include "AstNode.hpp"
#include "ExpressionNode.hpp"

#include <string>


class TerminalNode : public ExpressionNode
{
public:
    /**
     * Default constructor.
     * @param value The string value of the terminal.
     * @param type The type of the token as returned by the scanner.
     */
    TerminalNode(const std::string& value, const int type);

    /**
     * Alternate constructor that defaults the type to something.
     * I wanted to be able to create a dummy terminal node from Lemon without
     * having to know the values of the tokens, because otherwise my parser
     * would have to include the header file that's generated from itself, and
     * that just rubbed me the wrong way.
     */
    ///@{
    static TerminalNode* createDummyIdentifierTerminalNode();
    static TerminalNode* createStringTerminalNode(const std::string& str);
    static TerminalNode* createNumberTerminalNode(const std::string& str);
    ///@}

    ~TerminalNode();

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
     * Determines if the any of this node's children are always true.
     * Overridden from ExpressionNode.
     */
    bool anyIsAlwaysTrue() const WARN_UNUSED_RESULT;

    /**
     * Determines if the there is an empty password.
     * Overridden from ExpressionNode.
     */
    QueryRisk::EmptyPassword emptyPassword() const WARN_UNUSED_RESULT;

    /**
     * Determines if the evaluation of this node results in a number.
     * Overridden from ExpressionNode.
     */
    bool resultsInValue() const WARN_UNUSED_RESULT;

    /**
     * Determines if the evaluation of this node results in a string.
     * Overridden from ExpressionNode.
     */
    bool resultsInString() const WARN_UNUSED_RESULT;

    /**
     * Gets the value of this expression.
     * Overridden from ExpressionNode.
     */
    std::string getValue() const WARN_UNUSED_RESULT;

    /**
     * Determines type.
     */
    ///@{
    bool isNumber() const;
    bool isIdentifier() const;
    bool isString() const;
    ///@}

private:
    const std::string value_;
    const int type_;

    TerminalNode(const TerminalNode& rhs);
    TerminalNode& operator=(const TerminalNode& rhs);
};
#endif  // SRC_TERMINALNODE_HPP_
