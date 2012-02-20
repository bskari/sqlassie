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

#include "AttackProbabilities.hpp"
#include "clearStack.hpp"
#include "BayesException.hpp"
#include "DlibProbabilities.hpp"
#include "huginParser.tab.hpp"
#include "huginScanner.yy.hpp"
#include "Logger.hpp"
#include "nullptr.hpp"
#include "QueryRisk.hpp"

#include "dlib/bayes_utils.h"
#include "dlib/graph_utils.h"
#include "dlib/graph.h"
#include "dlib/directed_graph.h"
#include <string>
#include <fstream>
#include <exception>
#include <stack>
#include <cassert>

using std::string;
using std::ifstream;
using std::bad_alloc;
using std::stack;
using dlib::bayes_node_utils::set_node_value;
using dlib::bayes_node_utils::set_node_as_evidence;
using dlib::bayesian_network_join_tree;

// Stuff from the parser
extern int hugin_parse(DlibProbabilities::bayes_net* network, bool firstTime, void* scanner);
extern stack<string> identifiers;
extern stack<string> numbers;


static const int CACHE_SIZE = 5;


DlibProbabilities::DlibProbabilities() :
	dataAccessJt_(),
	bypassAuthenticationJt_(),
	dataModificationJt_(),
	fingerprintingJt_(),
	schemaJt_(),
	denialOfServiceJt_(),
	dataAccessNet_(),
	bypassAuthenticationNet_(),
	dataModificationNet_(),
	fingerprintingNet_(),
	schemaNet_(),
	denialOfServiceNet_(),
	dataAccessMap_(CACHE_SIZE),
	bypassAuthenticationMap_(CACHE_SIZE),
	dataModificationMap_(CACHE_SIZE),
	fingerprintingMap_(CACHE_SIZE),
	schemaMap_(CACHE_SIZE),
	denialOfServiceMap_(CACHE_SIZE)
{
	DlibProbabilities::bayes_net* bayesNets[6] = {
		&dataAccessNet_,
		&bypassAuthenticationNet_,
		&dataModificationNet_,
		&fingerprintingNet_,
		&schemaNet_,
		&denialOfServiceNet_
	};
	const char* netFileNames[6] = {
		"dataAccess.net",
		"bypassAuthentication.net",
		"dataModification.net",
		"fingerprinting.net",
		"schema.net",
		"denialOfService.net"
	};
	join_tree_type* joinTrees[6] = {
		&dataAccessJt_,
		&bypassAuthenticationJt_,
		&dataModificationJt_,
		&fingerprintingJt_,
		&schemaJt_,
		&denialOfServiceJt_
	};
	const size_t expectedNodes[6] = {19, 15, 14, 24, 21, 7};
	
	assert(
		sizeof(bayesNets) / sizeof(bayesNets[0]) ==
		sizeof(netFileNames) / sizeof(netFileNames[0]) &&
		sizeof(netFileNames) / sizeof(netFileNames[0]) ==
		sizeof(joinTrees) / sizeof(joinTrees[0]) &&
		sizeof(joinTrees) / sizeof(joinTrees[0]) ==
		sizeof(expectedNodes) / sizeof(expectedNodes[6]) &&
		"Arrays used for initialization should be the same size"
	);
	
	const int SIZE = sizeof(bayesNets) / sizeof(bayesNets[0]);
	
	for (int i = 0; i < SIZE; ++i)
	{
		if (0 != loadNetwork(netFileNames[i], bayesNets[i]))
		{
			throw BayesException(
				string("Unable to load Bayesian network file: ") + netFileNames[i]
			);
		}
		
		// Populate the join_tree with data from the Bayesian network.
		create_moral_graph(*bayesNets[i], *joinTrees[i]);
		
		// This needs to be checked before calling create_join_tree because the
		// expectedNodes has the total number of nodes, but calling
		// number_of_nodes after create_join_tree returns the number of
		// non-internal nodes
		if (expectedNodes[i] != joinTrees[i]->number_of_nodes())
		{
			throw BayesException(
				string(netFileNames[i]) + " has an incorrect number of nodes"
			);
		}
		
		create_join_tree(*joinTrees[i], *joinTrees[i]);
	}
}


DlibProbabilities::~DlibProbabilities()
{
}


double DlibProbabilities::getProbabilityOfAccessAttack(const QueryRisk& qr)
{
	// This should be the order of the nodes in the Hugin net file
	enum NODE_TYPES
	{
		GlobalVariables,
		IfStmts,
		StringManipulation,
		HexStrings,
		OrAlwaysTrue,
		ConditionalModification, // Non-evidence node
		CommentedConditionals,
		DetectionEvasion, // Non-evidence node
		StringStmts,
		BruteForce,
		ConditionalStmts, // Non-evidence node
		UnionStmts,
		BenchmarkStmts,
		CommentedQuotes,
		AlwaysTrueConditional,
		DataAccess, // Non-evidence node
		SensitiveTables,
		UnionAllStmts,
		OrStmts
	};
	assert(
		static_cast<int>(OrStmts) + 1 == dataAccessNet_.number_of_nodes() &&
		"The number of nodes loaded from file and the number of states in the nodes enum should match"
	);
	
	int states[static_cast<int>(OrStmts) + 1];
	
	states[GlobalVariables] = qr.globalVariables ? 0 : 1;
	states[IfStmts] = qr.ifStatements ? 0 : 1;
	states[StringManipulation] = (qr.stringManipulationStatements <= 3)
		? qr.stringManipulationStatements : 4;
	states[HexStrings] = qr.hexStrings ? 0 : 1;
	states[OrAlwaysTrue] = 
		(qr.orStatements && qr.alwaysTrue && qr.alwaysTrueConditional) ? 0 : 1;
	states[CommentedConditionals] = qr.commentedConditionals ? 0 : 1;
	states[StringStmts] = (qr.userStatements || qr.fingerprintingStatements
		|| qr.globalVariables) ? 0 : 1;
	states[BruteForce] = qr.bruteForceCommands ? 0 : 1;
	states[UnionStmts] = qr.unionStatements ? 0 : 1;
	states[BenchmarkStmts] = qr.benchmarkStatements ? 0 : 1;
	states[CommentedQuotes] = qr.commentedQuotes ? 0 : 1;
	states[AlwaysTrueConditional] = qr.alwaysTrueConditional ? 0 : 1;
	states[SensitiveTables] = qr.sensitiveTables ? 0 : 1;
	states[UnionAllStmts] = qr.unionAllStatements ? 0 : 1;
	states[OrStmts] = qr.orStatements ? 0 : 1;
	
	const int evidenceNodeNumbers[] = {
		GlobalVariables,
		IfStmts,
		StringManipulation,
		HexStrings,
		OrAlwaysTrue,
		// ConditionalModification, // Non-evidence node
		CommentedConditionals,
		// DetectionEvasion, // Non-evidence node
		StringStmts,
		BruteForce,
		// ConditionalStmts, // Non-evidence node
		UnionStmts,
		BenchmarkStmts,
		CommentedQuotes,
		AlwaysTrueConditional,
		// DataAccess, // Non-evidence node
		SensitiveTables,
		UnionAllStmts,
		OrStmts
	};
	
	const int SIZE = sizeof(evidenceNodeNumbers) / sizeof(evidenceNodeNumbers[0]);
	const int ATTACK_STATE = 0;
	return computeProbabilityOfState(
		ATTACK_DATA_ACCESS,
		DataAccess,
		ATTACK_STATE,
		evidenceNodeNumbers,
		states,
		SIZE
	);
}


double DlibProbabilities::getProbabilityOfBypassAttack(const QueryRisk& qr)
{
	// This should be the order of the nodes in the Hugin net file
	enum NODE_TYPES
	{
		OrAlwaysTrue,
		BypassAuthentication, // Non-evidence node
		HexStrings,
		BruteForce,
		DetectionEvasion, // Non-evidence node
		CommentedQuotes,
		StringStmts,
		GlobalVariables,
		UnionStmts,
		AlwaysTrueConditional,
		OrStmts,
		StringManipulation,
		EmptyPassword,
		ConditionalModification, // Non-evidence node
		CommentedConditionals
	};
	assert(
		static_cast<int>(CommentedConditionals) + 1 == bypassAuthenticationNet_.number_of_nodes() &&
		"The number of nodes loaded from file and the number of states in the nodes enum should match"
	);
	
	int states[static_cast<int>(CommentedConditionals) + 1];
	
	states[OrAlwaysTrue] =
		(qr.alwaysTrue && qr.orStatements && qr.alwaysTrueConditional);
	states[HexStrings] = qr.hexStrings ? 0 : 1;
	states[BruteForce] = qr.bruteForceCommands ? 0 : 1;
	states[CommentedQuotes] = qr.commentedQuotes ? 0 : 1;
	states[StringStmts] = (qr.userStatements || qr.fingerprintingStatements
		|| qr.globalVariables) ? 0 : 1;
	states[GlobalVariables] = qr.globalVariables ? 0 : 1;
	states[UnionStmts] = (qr.unionStatements || qr.unionAllStatements) ? 0 : 1;
	states[AlwaysTrueConditional] = qr.alwaysTrueConditional ? 0 : 1;
	states[OrStmts] = qr.orStatements ? 0 : 1;
	states[StringManipulation] = (qr.stringManipulationStatements <= 3)
		? qr.stringManipulationStatements : 4;
	
	switch (qr.emptyPassword)
	{
	case QueryRisk::PASSWORD_EMPTY:
		states[EmptyPassword] = 0;
		break;
	case QueryRisk::PASSWORD_NOT_EMPTY:
		states[EmptyPassword] = 1;
		break;
	case QueryRisk::PASSWORD_NOT_USED:
		// Don't set the state at all - it will be ignored and not set
		break;
	default:
		Logger::log(Logger::ERROR) << "Unexpected value of qr.emptyPassword " << qr.emptyPassword;
		assert(false);
		const_cast<QueryRisk&>(qr).emptyPassword = QueryRisk::PASSWORD_NOT_USED;
	}
	
	states[CommentedConditionals] = qr.commentedConditionals ? 0 : 1;
	
	const int evidenceNodeNumbersWithPassword[] = {
		// OrAlwaysTrue, // Non-evidence node
		// BypassAuthentication, // Non-evidence node
		HexStrings,
		BruteForce,
		// DetectionEvasion, // Non-evidence node
		CommentedQuotes,
		StringStmts,
		GlobalVariables,
		UnionStmts,
		AlwaysTrueConditional,
		OrStmts,
		StringManipulation,
		EmptyPassword,
		// ConditionalModification, // Non-evidence node
		CommentedConditionals
	};
	const int evidenceNodeNumbersWithoutPassword[] = {
		// OrAlwaysTrue, // Non-evidence node
		// BypassAuthentication, // Non-evidence node
		HexStrings,
		BruteForce,
		// DetectionEvasion, // Non-evidence node
		CommentedQuotes,
		StringStmts,
		GlobalVariables,
		UnionStmts,
		AlwaysTrueConditional,
		OrStmts,
		StringManipulation,
		// ConditionalModification, // Non-evidence node
		CommentedConditionals
	};
	
	assert(
		sizeof(evidenceNodeNumbersWithPassword)
			- sizeof(evidenceNodeNumbersWithoutPassword)
				== sizeof(evidenceNodeNumbersWithPassword[0]) &&
		"Evidence node numbers with and without password should differ by only one element"
	);
	
	int SIZE;
	const int* evidenceNodeNumbers;
	if (QueryRisk::PASSWORD_NOT_USED == qr.emptyPassword)
	{
		SIZE = sizeof(evidenceNodeNumbersWithoutPassword) 
			/ sizeof(evidenceNodeNumbersWithoutPassword[0]);
		evidenceNodeNumbers = evidenceNodeNumbersWithoutPassword;
	}
	else
	{
		SIZE = sizeof(evidenceNodeNumbersWithPassword) 
			/ sizeof(evidenceNodeNumbersWithPassword[0]);
		evidenceNodeNumbers = evidenceNodeNumbersWithPassword;
	}
	
	const int ATTACK_STATE = 0;
	return computeProbabilityOfState(
		ATTACK_BYPASS_AUTHENTICATION, 
		BypassAuthentication,
		ATTACK_STATE,
		evidenceNodeNumbers,
		states,
		SIZE
	);
}


double DlibProbabilities::getProbabilityOfModificationAttack(const QueryRisk& qr)
{
	// This should be the order of the nodes in the Hugin net file
	enum NODE_TYPES
	{
		DetectionEvasion, // Non-evidence node
		HexStrings,
		StringStmts,
		DataModification, // Non-evidence node
		Insert,
		ConditionalModification, // Non-evidence node
		GlobalVariables,
		BruteForce,
		OrStmts,
		AlwaysTrue,
		StringManipulation,
		CommentedConditionals,
		CommentedQuotes,
		SensitiveTables
	};
	assert(
		static_cast<int>(SensitiveTables) + 1 == 
			dataModificationNet_.number_of_nodes() &&
		"The number of nodes loaded from file and the number of states in the nodes enum should match"
	);
	
	int states[static_cast<int>(SensitiveTables) + 1];
	
	states[HexStrings] = qr.hexStrings ? 0 : 1;
	states[StringStmts] = (qr.userStatements || qr.fingerprintingStatements
		|| qr.globalVariables) ? 0 : 1;
	states[Insert] = (QueryRisk::TYPE_INSERT == qr.queryType) ? 0 : 1;
	states[GlobalVariables] = qr.globalVariables ? 0 : 1;
	states[BruteForce] = qr.bruteForceCommands ? 0 : 1;
	states[OrStmts] = qr.orStatements ? 0 : 1;
	states[AlwaysTrue] = qr.alwaysTrue ? 0 : 1;
	states[StringManipulation] = (qr.stringManipulationStatements <= 3) 
		? qr.stringManipulationStatements : 4;
	states[CommentedConditionals] = qr.commentedConditionals ? 0 : 1;
	states[CommentedQuotes] = qr.commentedQuotes ? 0 : 1;
	states[SensitiveTables] = qr.sensitiveTables ? 0 : 1;
	
	const int evidenceNodeNumbers[] = {
		// DetectionEvasion, // Non-evidence node
		HexStrings,
		StringStmts,
		// DataModification, // Non-evidence node
		Insert,
		// ConditionalModification, // Non-evidence node
		GlobalVariables,
		BruteForce,
		OrStmts,
		AlwaysTrue,
		StringManipulation,
		CommentedConditionals,
		CommentedQuotes,
		SensitiveTables
	};
	
	const int SIZE = sizeof(evidenceNodeNumbers) / sizeof(evidenceNodeNumbers[0]);
	const int ATTACK_STATE = 0;
	return computeProbabilityOfState(
		ATTACK_DATA_MODIFICATION,
		DataModification,
		ATTACK_STATE,
		evidenceNodeNumbers,
		states,
		SIZE
	);
}


double DlibProbabilities::getProbabilityOfFingerprintingAttack(const QueryRisk& qr)
{
	// This should be the order of the nodes in the Hugin net file
	enum NODE_TYPES
	{
		MySqlComments,
		MySqlStringConcat,
		DataAccess, // Non-evidence node
		GlobalVariables,
		Select,
		StringManipulation,
		OrStmts,
		ConditionalModification, // Non-evidence node
		IfStmts,
		CommentedQuotes,
		Fingerprinting, // Non-evidence node
		BruteForce,
		CommentedConditionals,
		ConditionalStmts, // Non-evidence node
		HexStrings,
		UnionStmts,
		MySqlVersionComments,
		DetectionEvasion, // Non-evidence node
		FingerprintingStmts,
		UserStmts,
		AlwaysTrueConditional,
		BenchmarkStmts,
		StringStmts,
		OrAlwaysTrue
	};
	assert(
		static_cast<int>(OrAlwaysTrue) + 1 == 
			fingerprintingNet_.number_of_nodes() &&
		"The number of nodes loaded from file and the number of states in the nodes enum should match"
	);
	
	int states[static_cast<int>(OrAlwaysTrue) + 1];
	
	states[MySqlComments] = qr.mySqlComments ? 0 : 1;
	states[MySqlStringConcat] = qr.mySqlStringConcat ? 0 : 1;
	states[GlobalVariables] = qr.globalVariables ? 0 : 1;
	states[Select] = (QueryRisk::TYPE_SELECT == qr.queryType) ? 0 : 1;
	states[StringManipulation] =  (qr.stringManipulationStatements <= 3)
		? qr.stringManipulationStatements : 4;
	states[OrStmts] = qr.orStatements ? 0 : 1;
	states[IfStmts] = qr.ifStatements ? 0 : 1;
	states[CommentedQuotes] = qr.commentedQuotes ? 0 : 1;
	states[FingerprintingStmts] = qr.fingerprintingStatements ? 0 : 1;
	states[BruteForce] = qr.bruteForceCommands ? 0 : 1;
	states[CommentedConditionals] = qr.commentedConditionals ? 0 : 1;
	states[HexStrings] = qr.hexStrings ? 0 : 1;
	states[UnionStmts] = (qr.unionStatements || qr.unionAllStatements) ? 0 : 1;
	states[MySqlVersionComments] = qr.mySqlVersionedComments ? 0 : 1;
	states[UserStmts] = qr.userStatements ? 0 : 1;
	states[AlwaysTrueConditional] = qr.alwaysTrueConditional ? 0 : 1;
	states[BenchmarkStmts] = qr.benchmarkStatements ? 0 : 1;
	states[StringStmts] =
		(qr.userStatements || qr.fingerprintingStatements
			|| qr.globalVariables) ? 0 : 1;
	states[OrAlwaysTrue] = 
		(qr.alwaysTrue && qr.orStatements && qr.alwaysTrueConditional) ? 0 : 1;
	
	const int evidenceNodeNumbers[] = {
		MySqlComments,
		MySqlStringConcat,
		// DataAccess, // Non-evidence node
		GlobalVariables,
		Select,
		StringManipulation,
		OrStmts,
		// ConditionalModification, // Non-evidence node
		IfStmts,
		CommentedQuotes,
		// Fingerprinting, // Non-evidence node
		BruteForce,
		CommentedConditionals,
		// ConditionalStmts, // Non-evidence node
		HexStrings,
		UnionStmts,
		MySqlVersionComments,
		// DetectionEvasion, // Non-evidence node
		FingerprintingStmts,
		UserStmts,
		AlwaysTrueConditional,
		BenchmarkStmts,
		StringStmts,
		OrAlwaysTrue
	};
	
	const int SIZE = sizeof(evidenceNodeNumbers) / sizeof(evidenceNodeNumbers[0]);
	const int ATTACK_STATE = 0;
	return computeProbabilityOfState(
		ATTACK_FINGERPRINTING,
		Fingerprinting,
		ATTACK_STATE,
		evidenceNodeNumbers,
		states,
		SIZE
	);
}


double DlibProbabilities::getProbabilityOfSchemaAttack(const QueryRisk& qr)
{
	// This should be the order of the nodes in the Hugin net file
	enum NODE_TYPES
	{
		OrStmts,
		OrderByNumber,
		GlobalVariables,
		BruteForce,
		CommentedQuotes,
		IfStmts,
		StringStmts,
		DataAccess, // Non-evidence node
		InformationSchema,
		HexStrings,
		ConditionalModification, // Non-evidence node
		DetectionEvasion, // Non-evidence node
		Schema, // Non-evidence node
		UnionStmts,
		CommentedConditionals,
		ConditionalStmts, // Non-evidence node
		BenchmarkStmts,
		OrAlwaysTrue,
		AlwaysTrueConditional,
		StringManipulation,
		Select
	};
	assert(
		static_cast<int>(Select) + 1 == schemaNet_.number_of_nodes() &&
		"The number of nodes loaded from file and the number of states in the nodes enum should match"
	);
	
	int states[static_cast<int>(Select) + 1];
	
	states[OrStmts] = qr.orStatements ? 0 : 1;
	states[OrderByNumber] = qr.orderByNumber ? 0 : 1;
	states[GlobalVariables] = qr.globalVariables ? 0 : 1;
	states[BruteForce] = qr.bruteForceCommands ? 0 : 1;
	states[CommentedQuotes] = qr.commentedQuotes ? 0 : 1;
	states[IfStmts] = qr.ifStatements ? 0 : 1;
	states[StringStmts] = 
		((qr.userStatements || qr.fingerprintingStatements
			|| qr.globalVariables) ? 0 : 1);
	states[InformationSchema] = qr.informationSchema ? 0 : 1;
	states[HexStrings] = qr.hexStrings ? 0 : 1;
	states[UnionStmts] = (qr.unionStatements || qr.unionAllStatements) ? 0 : 1;
	states[CommentedConditionals] = qr.commentedConditionals ? 0 : 1;
	states[BenchmarkStmts] = qr.benchmarkStatements ? 0 : 1;
	states[OrAlwaysTrue] =
		(qr.alwaysTrue && qr.orStatements && qr.alwaysTrueConditional ? 0 : 1);
	states[AlwaysTrueConditional] = qr.alwaysTrueConditional ? 0 : 1;
	states[StringManipulation] = 
		(qr.stringManipulationStatements <= 3 ? qr.stringManipulationStatements : 4);
	states[Select] = (QueryRisk::TYPE_SELECT == qr.queryType) ? 0 : 1;
	
	const int evidenceNodeNumbers[] = {
		OrStmts,
		OrderByNumber,
		GlobalVariables,
		BruteForce,
		CommentedQuotes,
		IfStmts,
		StringStmts,
		// DataAccess, // Non-evidence node
		InformationSchema,
		HexStrings,
		// ConditionalModification, // Non-evidence node
		// DetectionEvasion, // Non-evidence node
		// Schema, // Non-evidence node
		UnionStmts,
		CommentedConditionals,
		// ConditionalStmts, // Non-evidence node
		BenchmarkStmts,
		OrAlwaysTrue,
		AlwaysTrueConditional,
		StringManipulation,
		Select
	};
	
	const int SIZE = sizeof(evidenceNodeNumbers) / sizeof(evidenceNodeNumbers[0]);
	const int ATTACK_STATE = 0;
	return computeProbabilityOfState(
		ATTACK_SCHEMA,
		Schema,
		ATTACK_STATE,
		evidenceNodeNumbers,
		states,
		SIZE
	);
}


double DlibProbabilities::getProbabilityOfDenialAttack(const QueryRisk& qr)
{
	// This should be the order of the nodes in the Hugin net file
	enum NODE_TYPES
	{
		AlwaysTrue,
		SlowRegex,
		Benchmark,
		Joins,
		DenialOfService, // Non-evidence node
		CrossJoin,
		RegexLength
	};
	assert(
		static_cast<int>(RegexLength) + 1 == denialOfServiceNet_.number_of_nodes() &&
		"The number of nodes loaded from file and the number of states in the nodes enum should match"
	);
	
	int states[static_cast<int>(RegexLength) + 1];
	
	states[AlwaysTrue] = qr.alwaysTrue ? 0 : 1;
	states[SlowRegex] = qr.slowRegexes ? 0 : 1;
	states[Benchmark] = qr.benchmarkStatements ? 0 : 1;
	states[Joins] = (qr.joinStatements <= 4 ? qr.joinStatements : 5);
	states[CrossJoin] = qr.globalVariables ? 0 : 1;
	states[RegexLength] = (qr.regexLength / 5 < 5) ? (qr.regexLength / 5) : 5;
	
	const int evidenceNodeNumbers[] = {
		AlwaysTrue,
		SlowRegex,
		Benchmark,
		Joins,
		// DenialOfService, // Non-evidence node
		CrossJoin,
		RegexLength
	};
	
	const int SIZE = sizeof(evidenceNodeNumbers) / sizeof(evidenceNodeNumbers[0]);
	const int ATTACK_STATE = 0;
	return computeProbabilityOfState(
		ATTACK_DENIAL_OF_SERVICE,
		DenialOfService,
		ATTACK_STATE,
		evidenceNodeNumbers,
		states,
		SIZE
	);
}


int DlibProbabilities::loadNetwork(
	const char* const fileName,
	bayes_net* network
)
{
	assert(
		nullptr != fileName &&
		"fileName should not be null"
	);
	
	ifstream fin(fileName);
	if (!fin)
	{
		return 1;
	}
	
	string file;
	string line;
	while (getline(fin, line))
	{
		file += line + "\n";
	}
	fin.close();
	
	// We have to call the parsing twice - once to build the network's
	// structure, and once to set the probabilities
	for (int i = 0; i < 2; ++i)
	{
		// Parse the file
		yyscan_t scanner;
		if (0 != hugin_lex_init(&scanner))
		{
			throw bad_alloc();
		}
		YY_BUFFER_STATE bufferState;
		bufferState = hugin__scan_string(file.c_str(), scanner);
		if (nullptr == bufferState)
		{
			throw bad_alloc();
		}
		const bool firstTime = (i == 0);
		const int status = hugin_parse(network, firstTime, scanner);

		// Cleanup
		hugin__delete_buffer(bufferState, scanner);
		hugin_lex_destroy(scanner);
		#ifndef NDEBUG
			if (0 == status)
			{
				assert(
					identifiers.empty() &&
					numbers.empty() &&
					"After parsing a Hugins network file, stacks should be empty"
				);
			}
		#endif
		clearStack(&identifiers);
		clearStack(&numbers);
		
		// Quit early if parsing failed
		if (0 != status)
		{
			return status;
		}
	}
	// If we got here, then status must be okay
	return 0;
}

double DlibProbabilities::computeProbabilityOfState(
	const ATTACK_TYPE type,
	const int node,
	const int state,
	const int evidenceNodes[],
	const int evidenceStates[],
	const int evidenceSize
)
{
	bayes_net* net = nullptr;
	join_tree_type* joinTree = nullptr;
	DlibProbabilities::EvidenceMap* Map = nullptr;
	
	switch (type)
	{
		case ATTACK_DATA_ACCESS:
			net = &dataAccessNet_;
			joinTree = &dataAccessJt_;
			Map = &dataAccessMap_;
			break;
		case ATTACK_BYPASS_AUTHENTICATION:
			net = &bypassAuthenticationNet_;
			joinTree = &bypassAuthenticationJt_;
			Map = &bypassAuthenticationMap_;
			break;
		case ATTACK_DATA_MODIFICATION:
			net = &dataModificationNet_;
			joinTree = &dataModificationJt_;
			Map = &dataModificationMap_;
			break;
		case ATTACK_FINGERPRINTING:
			net = &fingerprintingNet_;
			joinTree = &fingerprintingJt_;
			Map = &fingerprintingMap_;
			break;
		case ATTACK_SCHEMA:
			net = &schemaNet_;
			joinTree = &schemaJt_;
			Map = &schemaMap_;
			break;
		case ATTACK_DENIAL_OF_SERVICE:
			net = &denialOfServiceNet_;
			joinTree = &denialOfServiceJt_;
			Map = &denialOfServiceMap_;
			break;
		default:
			Logger::log(Logger::ERROR) << "Unexpected attack type " << type;
			assert(false);
			return 0.0;
	}
	
	// Check to see if the data is cached
	const Evidence encodedEvidence =
		encodeEvidence(evidenceNodes, evidenceStates, evidenceSize);
	if (Map->exists(encodedEvidence))
	{
		return (*Map)[encodedEvidence];
	}
	
	// if it's not cached then compute it
	for (int i = 0; i < evidenceSize; ++i)
	{
		const int NODE_NUMBER = evidenceNodes[i];
		set_node_value(*net, NODE_NUMBER, evidenceStates[NODE_NUMBER]);
		set_node_as_evidence(*net, NODE_NUMBER);
	}
	
	// Compute the probabilities of the nodes given what we know
	bayesian_network_join_tree computed(*net, *joinTree);

	const double probability = computed.probability(node)(state);
	(*Map)[encodedEvidence] = probability;
	return probability;
}


DlibProbabilities::Evidence DlibProbabilities::encodeEvidence(
	const int nodeNumbers[],
	const int states[],
	const int size
)
{
	// Use 3 bits for each value
	assert(
		static_cast<unsigned int>(size) < ((sizeof(Evidence) * 8) / 3) &&
		"Not enough bits in Evidence type to encode the evidence nodes"
	);
	Evidence e = 0;
	
	for (int i = 0; i < size; ++i)
	{
		const int NODE_NUMBER = nodeNumbers[i];
		assert(
			states[NODE_NUMBER] < 8 &&
			"Encoding uses 3 bits, but provided evidence has value >= 8"
		);
		e = (e << 3) | (states[NODE_NUMBER]);
	}
	return e;
}
