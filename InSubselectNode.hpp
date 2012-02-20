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

#ifndef IN_SUBSELECT_NODE_HPP
#define IN_SUBSELECT_NODE_HPP

#include "AstNode.hpp"
#include "ExpressionNode.hpp"
#include "InValuesListNode.hpp"
#include "QueryRisk.hpp"
#include "warnUnusedResult.h"

#include <string>

/**
 * Parse tree node that represents MySQL commands like this:
 * someExpression IN (SELECT value FROM table ...).
 * Because determining the truth of this node would require actually accessing
 * the database, it is assumed to always be false.
 * @author Brandon Skari
 * @date November 6 2011
 */

class InSubselectNode : public InValuesListNode
{
public:
	/**
	 * Default constructor.
	 */
	InSubselectNode(const ExpressionNode* const expression);
	
	virtual ~InSubselectNode();
	
	/**
	 * Overridden from AstNode.
	 */
	virtual AstNode* copy() const WARN_UNUSED_RESULT;
	
	/**
	 * Determines if the conditionals are always true.
	 * Overridden from InValuesListNode.
	 */
	virtual bool isAlwaysTrue() const WARN_UNUSED_RESULT;
	
	/**
	 * Determines if any of this node's children are always true.
	 * Overridden from InValuesListNode.
	 */
	virtual bool anyIsAlwaysTrue() const WARN_UNUSED_RESULT;

private:
	
	InSubselectNode(const InSubselectNode& rhs);
	InSubselectNode& operator=(const InSubselectNode& rhs);
};
#endif
