%{
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

#include "clearStack.hpp"
#include "Logger.hpp"
#include "warnUnusedResult.h"

#include "dlib/bayes_utils.h"
#include "dlib/graph_utils.h"
#include "dlib/graph.h"
#include "dlib/directed_graph.h"
#include <stack>
#include <map>
#include <string>
#include <vector>
#include <boost/lexical_cast.hpp>

/**
 * Parser for Hugin-formatted Bayesian network files.
 * @author Brandon Skari
 * @date May 8 2011
 */

const double PROBABILITY_SUM_TOLERANCE = 0.0000001;

typedef dlib::directed_graph<dlib::bayes_node>::kernel_1a_c bayes_net;

/* These declarations are needed so the compiler doesn't barf */
int hugin_lex(void* scanner);
void hugin_error(bayes_net*, bool, void*, const char* s);

/**
 * Sets the probabilities for a given node. The names of the parents should be
 * in the parents vector and the probability values in the probabilities
 * vector.
 * @return 0 on success.
 */
///@{
static int setProbabilities(
	const std::string& node,
	bayes_net* network
) WARN_UNUSED_RESULT;

static int setProbabilities(
	const std::string& node,
	bayes_net* network, 
	dlib::assignment* parentStates,
	const int parentNumber
) WARN_UNUSED_RESULT;
///@}

extern char* hugin_text;

extern std::stack<std::string> hugin_identifiers;
extern std::map<std::string, int> hugin_nodesNumbers;
extern std::stack<std::string> hugin_numbers;

static int nodeCount;
static std::vector<std::string> parents;
static std::map<std::string, int> numberOfStates;
static std::stack<double> probabilities;
static bool networkSizeHasBeenSet;
static int statesCount;

%}

%name-prefix="hugin_"

%parse-param { bayes_net* network }
%parse-param { bool firstTime }
%parse-param { void* scanner }
%lex-param { void* scanner }

/* Tokens */
%token STRING
%token IDENTIFIER
%token NUMBER

%token NET
%token POTENTIAL
%token DATA
%token STATES
%token LABEL
%token NODE

%token EQUAL
%token LEFT_BRACE RIGHT_BRACE
%token LEFT_PARENTHESE RIGHT_PARENTHESE
%token SEMICOLON
%token PIPE

%token ERROR

%%

begin:
	NET LEFT_BRACE netParametersList RIGHT_BRACE nodesList
		{
		}
	;

netParametersList:
	netParameter
		{
			// I need to reset these at the beginning of any parsing.
			// Because the netParameter action is always guaranteed to run
			// before the node parsing actions, I can put it here and it should
			// work okay - I just don't know where else I can put this code and
			// have it work without requiring external action by the user.
			nodeCount = 0;
			parents.clear();
			numberOfStates.clear();
			clearStack(&probabilities);
			networkSizeHasBeenSet = false;
			statesCount = 0;
			// These are external, but should be cleared too
			clearStack(&hugin_identifiers);
			hugin_nodesNumbers.clear();
			clearStack(&hugin_numbers);
		}
	| netParameter netParametersList
		{
		}
	;

netParameter:
	IDENTIFIER EQUAL STRING SEMICOLON
		{
			hugin_identifiers.pop();
		}
	| IDENTIFIER EQUAL LEFT_PARENTHESE numbersList RIGHT_PARENTHESE SEMICOLON
		{
			hugin_identifiers.pop();
		}
	;

nodesList:
	node nodesList
		{
		}
	| potentialList
		{
		}
	;

node:
	NODE IDENTIFIER LEFT_BRACE nodeParametersList RIGHT_BRACE
		{
			const std::string nodeName(hugin_identifiers.top());
			hugin_identifiers.pop();
			
			// Save the number of states this node has
			std::map<std::string, int>::const_iterator statesIter(
				numberOfStates.find(nodeName)
			);
			if (numberOfStates.end() == statesIter)
			{
				numberOfStates.insert(std::pair<std::string, int>(nodeName, statesCount));
			}
			// This can't be set until the network's structure has been created
			if (!firstTime)
			{
				dlib::bayes_node_utils::set_node_num_values(*network, nodeCount, statesCount);
			}
			statesCount = 0;
		
			// Save the name of the node
			std::map<std::string, int>::const_iterator nodeIter(
				hugin_nodesNumbers.find(nodeName)
			);
			if (hugin_nodesNumbers.end() != nodeIter)
			{
				YYERROR;
			}
			hugin_nodesNumbers.insert(std::pair<std::string, int>(nodeName, nodeCount));
			++nodeCount;
			
		}
	;

nodeParametersList:
	nodeParameter
		{
		}
	| nodeParameter nodeParametersList
		{
		}
	;

nodeParameter:
	STATES EQUAL statesList SEMICOLON
		{
		}
	| LABEL EQUAL STRING SEMICOLON
		{
		}
	| IDENTIFIER EQUAL LEFT_PARENTHESE numbersList RIGHT_PARENTHESE SEMICOLON
		{
			hugin_identifiers.pop();
		}
	| IDENTIFIER EQUAL STRING SEMICOLON
		{
			hugin_identifiers.pop();
		}
	;

statesList:
	LEFT_PARENTHESE statesStringsList RIGHT_PARENTHESE
		{
		}
	;

statesStringsList:
	STRING
		{
			++statesCount;
		}
	| STRING statesStringsList
		{
			++statesCount;
		}
	;

numbersList:
	NUMBER
		{
			hugin_numbers.pop();
		}
	| NUMBER numbersList
		{
			hugin_numbers.pop();
		}
	;

potentialList:
	potential
		{
		}
	| potential potentialList
		{
		}
	;

potential:
	POTENTIAL LEFT_PARENTHESE IDENTIFIER PIPE parentList RIGHT_PARENTHESE
		LEFT_BRACE DATA EQUAL dataList SEMICOLON RIGHT_BRACE
		{
			const std::string nodeName(hugin_identifiers.top());
			hugin_identifiers.pop();
			
			// The first call to the parser will just build the structure of
			// the network
			if (firstTime)
			{
				if (!networkSizeHasBeenSet)
				{
					networkSizeHasBeenSet = true;
					network->set_number_of_nodes(nodeCount);
				}
				
				// Add edges between all the parents to this node
				std::map<std::string, int>::const_iterator nodeIter(
					hugin_nodesNumbers.find(nodeName)
				);
				if (hugin_nodesNumbers.end() == nodeIter)
				{
					YYERROR;
				}
				const int nodeNumber = nodeIter->second;
				const std::vector<std::string>::const_iterator end(parents.end());
				for (
					std::vector<std::string>::const_iterator i(parents.begin());
					i != end;
					++i
				)
				{
					const std::map<std::string, int>::const_iterator parentIter(
						hugin_nodesNumbers.find(*i)
					);
					if (hugin_nodesNumbers.end() == parentIter)
					{
						YYERROR;
					}
					const int parentNumber = parentIter->second;
					
					network->add_edge(parentNumber, nodeNumber);
				}
			}
			// The second call to the parser will set the probabilities
			else
			{
				const int status = setProbabilities(nodeName, network);
				if (0 != status)
				{
					Logger::log(Logger::FATAL) <<
						"Error parsing Hugin Bayes net file: " <<
						"unable to set probabilities for node " <<
						nodeName;
				}
			}
			
			// Done adding the parents for this node, so clear the parents
			parents.clear();
		}
	;

parentList:
	/* empty - root node (and possibly others) have no parents */
		{
		}
	| IDENTIFIER parentList
		{
			parents.push_back(hugin_identifiers.top());
			hugin_identifiers.pop();
		}
	;

dataList:
	LEFT_PARENTHESE dataList dataList RIGHT_PARENTHESE
		{
		}
	| LEFT_PARENTHESE probabilityList RIGHT_PARENTHESE
		{
		}
	;

probabilityList:
	NUMBER
		{
			try
			{
				probabilities.push(boost::lexical_cast<double>(hugin_numbers.top()));
				hugin_numbers.pop();
			}
			catch (...)
			{
				YYERROR;
			}
		}
	| NUMBER probabilityList
		{
			try
			{
				probabilities.push(boost::lexical_cast<double>(hugin_numbers.top()));
				hugin_numbers.pop();
			}
			catch (...)
			{
				YYERROR;
			}
		}
	;

%%

void hugin_error(bayes_net*, bool, void*, const char* s)
{
	Logger::log(Logger::ERROR) << "Hugin parser error: " << s;
}

int setProbabilities(const std::string& node, bayes_net* network)
{
	// Add the parent states for the node
	dlib::assignment parentStates;
	std::vector<std::string>::const_iterator end(parents.end());
	for (
		std::vector<std::string>::const_iterator i(parents.begin());
		i != end;
		++i
	)
	{
		const std::map<std::string, int>::const_iterator parentIter(
			hugin_nodesNumbers.find(*i)
		);
		if (hugin_nodesNumbers.end() == parentIter)
		{
			return 1;
		}
		const int parentNumber = parentIter->second;
		
		parentStates.add(parentNumber, 0);
	}
	
	const int status = setProbabilities(
		node,
		network,
		&parentStates,
		parentStates.size() - 1
	);
	
	if (0 == status && probabilities.empty())
	{
		return 0;
	}
	return 1;
}

int setProbabilities(
	const std::string& node,
	bayes_net* network, 
	dlib::assignment* parentStates,
	const int parentNumber
)
{
	if (parentNumber < 0)
	{
		// All parent states are set, so set the probability
		const std::map<std::string, int>::const_iterator nodeNumberIter(
			hugin_nodesNumbers.find(node)
		);
		if (hugin_nodesNumbers.end() == nodeNumberIter)
		{
			Logger::log(Logger::FATAL) <<
				"Error parsing Hugin Bayes net file: " <<
				"invalid node number: " <<
				node;
			return 1;
		}
		const int nodeNumber = nodeNumberIter->second;
		
		const std::map<std::string, int>::const_iterator nodeStatesIter(
			numberOfStates.find(node)
		);
		if (numberOfStates.end() == nodeStatesIter)
		{
			Logger::log(Logger::FATAL) <<
				"Error parsing Hugin Bayes net file: " <<
				"invalid node number: " <<
				node;
			return 1;
		}
		const int numberOfNodeStates = nodeStatesIter->second;
		
		double totalProbability = 0.0;
		for (int state = 0; state < numberOfNodeStates; ++state)
		{
			assert(
				!probabilities.empty() &&
				"Needed probabilities and there were none in the stack"
			);
			if (probabilities.empty())
			{
				Logger::log(Logger::FATAL) <<
					"Error parsing Hugin Bayes net file: " <<
					"list of probabilities was too short";
				return 1;
			}
			
			const double probability = probabilities.top();
			probabilities.pop();
			totalProbability += probability;
			
			// Set the probability of the node having a given state, given the
			// states of its parents
			dlib::bayes_node_utils::set_node_probability(
				*network,
				nodeNumber,
				state,
				*parentStates,
				probability
			);
		}

		if (abs(totalProbability - 1.0) > PROBABILITY_SUM_TOLERANCE)
		{
			Logger::log(Logger::FATAL) <<
				"Error parsing Hugin Bayes net file: " <<
				"probabilities list for a given state didn't sum to 1, but to " <<
				abs(totalProbability - 1.0);
		}
		
		return 0;
	}
	
	const std::string parentNodeName(parents.at(parentNumber));
	
	const std::map<std::string, int>::const_iterator parentStatesIter(
		numberOfStates.find(parentNodeName)
	);
	if (numberOfStates.end() == parentStatesIter)
	{
		Logger::log(Logger::FATAL) <<
			"Error parsing Hugin Bayes net file: " <<
			"parent node not found";
		return 1;
	}
	const int numberParentStates = parentStatesIter->second;
	
	const std::map<std::string, int>::const_iterator parentNodeIter(
		hugin_nodesNumbers.find(parentNodeName)
	);
	if (hugin_nodesNumbers.end() == parentNodeIter)
	{
		Logger::log(Logger::FATAL) <<
			"Error parsing Hugin Bayes net file: " <<
			"parent node not found";
		return 1;
	}
	const int parentNodeNumber = parentNodeIter->second;
	
	// This has to be done in reverse because the probabilities are stored in a
	// stack and so they need to be handled in reverse order
	for (int i = numberParentStates - 1; i >= 0; --i)
	{
		(*parentStates)[parentNodeNumber] = i;
		const int status = setProbabilities(
			node,
			network,
			parentStates,
			parentNumber - 1
		);
		if (0 != status)
		{
			return status;
		}
	}
	
	return 0;
}
