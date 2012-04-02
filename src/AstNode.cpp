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

#include "nullptr.hpp"
#include "AstNode.hpp"

#include <vector>
#include <string>
#include <cassert>
#include <ostream>

using std::vector;
using std::string;
using std::ostream;


AstNode::AstNode(const string& name) :
	name_(name),
	children_()
{
}


AstNode::AstNode(const AstNode& rhs) :
	name_(rhs.name_),
	children_()
{
}


AstNode::~AstNode()
{
	const vector<const AstNode*>::const_iterator end(children_.end());
	for(vector<const AstNode*>::const_iterator i(children_.begin());
		i != end;
		++i)
	{
		delete *i;
	}
}


void AstNode::addCopyOfChildren(AstNode* additive) const
{
	const vector<const AstNode*>::const_iterator end = children_.end();
	for (vector<const AstNode*>::const_iterator i = children_.begin();
		i != end;
		++i)
	{
		additive->addChild((*i)->copy());
	}
}


void AstNode::addChild(const AstNode* child)
{
	assert(nullptr != child && "Attempted to add nullptr to AstNode children");
	assert(this != child && "Attempted to add this to AstNode children");
	children_.push_back(child);
}


AstNode* AstNode::copy() const
{
	AstNode* temp = new AstNode(*this);
	const vector<const AstNode*>::const_iterator end(children_.end());
	for(vector<const AstNode*>::const_iterator i(children_.begin());
		i != end;
		++i)
	{
		temp->addChild((*i)->copy());
	}
	return temp;
}


const string& AstNode::getName() const
{
	return name_;
}


void AstNode::print(
	ostream& out,
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


void AstNode::printChildren(ostream& out, const int depth, const char indent) const
{
	const vector<const AstNode*>::const_iterator end(children_.end());
	for (vector<const AstNode*>::const_iterator i(children_.begin());
		end != i;
		++i)
	{
		(*i)->print(out, depth, indent);
	}
}


ostream& operator<<(ostream& out, const AstNode& node)
{
	node.print(out);
	return out;
}
