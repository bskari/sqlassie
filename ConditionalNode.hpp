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

#ifndef CONDITIONAL_NODE_HPP
#define CONDITIONAL_NODE_HPP

#include "AstNode.hpp"
#include "QueryRisk.hpp"

#include <string>

/**
 * Pure virtual parse tree node that represents some kind of conditional
 * statement. Derived classes must implement isAlwaysTrue(), anyIsAlwaysTrue(),
 * copy() and emptyPassword().
 * @author Brandon Skari
 * @date December 9 2010
 */

class ConditionalNode : public AstNode
{
public:
	/**
	 * Default constructor.
	 * @param name What kind of ConditionalNode this is.
	 */
	ConditionalNode(const std::string& name);
	
	virtual ~ConditionalNode();
	
	/**
	 * Overridden from AstNode.
	 */
	virtual AstNode* copy() const = 0;
	
	/**
	 * Determines if the conditionals are always true.
	 */
	virtual bool isAlwaysTrue() const = 0;
	
	/**
	 * Determines if any of its children have an always true comparison.
	 */
	virtual bool anyIsAlwaysTrue() const = 0;
	
	/**
	 * Determines if the password is empty.
	 */
	virtual QueryRisk::EmptyPassword emptyPassword() const = 0;

private:
	ConditionalNode(const ConditionalNode& rhs);
	ConditionalNode& operator=(const ConditionalNode& rhs);
};
#endif
