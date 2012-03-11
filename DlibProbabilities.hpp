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

#ifndef DLIB_PROBABILITIES_HPP
#define DLIB_PROBABILITIES_HPP

#include "AttackProbabilities.hpp"
#include "LruCache.hpp"
#include "QueryRisk.hpp"
#include "warnUnusedResult.h"

#include <boost/cstdint.hpp>
#include <boost/thread/mutex.hpp>
#include "dlib/bayes_utils.h"
#include "dlib/graph.h"
#include "dlib/graph_utils.h"
#include "dlib/directed_graph.h"

/**
 * Implementation of AttackProbabilities that uses Bayesian networks and the
 * dlib library.
 * @author Brandon Skari
 * @date May 8 2011
 */


class DlibProbabilities : public AttackProbabilities
{
public:
	/**
	 * Default constructor.
	 * @throw BayesException A network was not loaded correctly from file.
	 */
	DlibProbabilities();
	
	~DlibProbabilities();
	
	/**
	 * Returns the probability of a given type of attack.
	 * Implemented from AttackProbabilities.
	 * @throw BayesException The probability was not correctly computed.
	 */
	///@{
	double getProbabilityOfAccessAttack(const QueryRisk& qr) WARN_UNUSED_RESULT;
	double getProbabilityOfBypassAttack(const QueryRisk& qr) WARN_UNUSED_RESULT;
	double getProbabilityOfModificationAttack(const QueryRisk& qr) WARN_UNUSED_RESULT;
	double getProbabilityOfFingerprintingAttack(const QueryRisk& qr) WARN_UNUSED_RESULT;
	double getProbabilityOfSchemaAttack(const QueryRisk& qr) WARN_UNUSED_RESULT;
	double getProbabilityOfDenialAttack(const QueryRisk& qr) WARN_UNUSED_RESULT;
	///@}
	
	typedef dlib::directed_graph<dlib::bayes_node>::kernel_1a_c bayes_net;
	
	typedef uint64_t Evidence;
	typedef LruCache<Evidence, double> EvidenceCache;
	
protected:
	/**
	 * Loads a Bayesian network from a Hugin net file.
	 * @param fileName The name of the Hugin net file.
	 * @param network The network to encode the information from the file.
	 * @return 0 on success.
	 */
	static int loadNetwork(const char* fileName, bayes_net* network);
	
private:
	enum ATTACK_TYPE
	{
		ATTACK_DATA_ACCESS,
		ATTACK_BYPASS_AUTHENTICATION,
		ATTACK_DATA_MODIFICATION,
		ATTACK_FINGERPRINTING,
		ATTACK_SCHEMA,
		ATTACK_DENIAL_OF_SERVICE,
		numAttackTypes
	};

	typedef dlib::set<unsigned long>::compare_1b_c set_type;
	typedef dlib::graph<set_type, set_type>::kernel_1a_c join_tree_type;

	join_tree_type joinTrees_[numAttackTypes];
	bayes_net bayesNets_[numAttackTypes];
	
	/**
	 * Convenvience function to compute the probability of a given node having
	 * a particular state given some evidence.
	 * @param type The type of attack to compute probabilities for.
	 * @param node Compute the probability of this node having a given state.
	 * @param state Compute the probability of a given node having this state.
	 * @param evidenceNodes The nodes that the provided evidence correspond to.
	 * @param evidenceStates The states of the evidence nodes.
	 * @param evidenceSize How many items are in the given evidence array.
	 */
	double computeProbabilityOfState(
		ATTACK_TYPE type,
		int node,
		int state,
		const int evidenceNodes[],
		const int evidenceStates[],
		int evidenceSize
	);
	
	/**
	 * Caches the probabilities from the Bayesian networks so they don't have
	 * to be calculated all the time.
	 */
	EvidenceCache* caches_[numAttackTypes];
	
	/**
	 * Encodes the evidence into an integral type so that I can use my
	 * LruCache for lookup.
	 */
	static Evidence encodeEvidence(
		const int nodeNumbers[],
		const int states[],
		const int size
	);

	boost::mutex computeMutex_;
	double computeEvidence(const Evidence&);
};

#endif
