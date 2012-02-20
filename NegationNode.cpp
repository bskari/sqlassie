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

#include "ExpressionNode.hpp"
#include "Logger.hpp"
#include "MySqlConstants.hpp"
#include "NegationNode.hpp"
#include "nullptr.hpp"
#include "QueryRisk.hpp"

#include <boost/regex.hpp>
#include <ctype.h>
#include <ostream>
#include <string>

using std::string;
using boost::regex;
using boost::regex_replace;
using boost::regex_match;


NegationNode::NegationNode() :
	ConditionalNode("Negation")
{
}


NegationNode::~NegationNode()
{
}


AstNode* NegationNode::copy() const
{
	NegationNode* const temp = new NegationNode();
	AstNode::addCopyOfChildren(temp);
	return temp;
}


bool NegationNode::isAlwaysTrue() const
{
	assert(1 == children_.size() && "NegationNode should have 1 child");
	
	const ExpressionNode* const expr = dynamic_cast<const ExpressionNode*>(
		children_.at(0)
	);
	assert(
		nullptr != expr &&
		"NegationNode should only an ExpressionNode child"
	);

	return !expr->isAlwaysTrue();
}


bool NegationNode::anyIsAlwaysTrue() const
{
	return NegationNode::isAlwaysTrue();
}


QueryRisk::EmptyPassword NegationNode::emptyPassword() const
{
	return QueryRisk::PASSWORD_NOT_USED;
}


void NegationNode::print(
	std::ostream& out,
	const int depth,
	const char indent
) const
{
	for (int i = 0; i < depth; ++i)
	{
		out << indent;
	}
	out << name_ << '\n';
	printChildren(out, depth + 1, indent);
}
