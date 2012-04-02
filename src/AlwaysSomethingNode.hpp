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

#ifndef ALWAYS_SOMETHING_NODE_HPP
#define ALWAYS_SOMETHING_NODE_HPP

#include "AstNode.hpp"
#include "ComparisonNode.hpp"
#include "warnUnusedResult.h"

#include <string>

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
	 * @param compareType The comparison type used, such as = or >.
	 */
	AlwaysSomethingNode(bool always, const std::string& compareType);
	
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
#endif
