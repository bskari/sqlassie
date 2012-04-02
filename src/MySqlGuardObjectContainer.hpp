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

#ifndef MY_SQL_GUARD_OBJECT_CONTAINER
#define MY_SQL_GUARD_OBJECT_CONTAINER

#include "AttackProbabilities.hpp"

#include <boost/thread.hpp>
#include <string>
#include <fstream>

/**
 * MySqlGuard uses a bunch of objects that really only need to be made once and
 * can be reused, like the Bayesian networks and the log files. Rather than
 * opening and closing those files constantly, this class just opens them up
 * once and provides a thread safe way to access them. This is a singleton
 * class.
 * @author Brandon Skari
 * @date January 12 2011
 */

class MySqlGuardObjectContainer
{
public:
	/**
	 * Initalizes the singleton instance if not done yet.
	 */
	static void initialize();

	/**
	 * Log a blocked query.
	 */
	static void logBlockedQuery(
		const std::string& query,
		const std::string& attackType,
		const double attackProbability
	);
	
	/**
	 * Calculates the probability of a given type of attack.
	 * @param qr The analyzed riskiness of a query.
	 * @throw BayesException The probability was not correctly computed.
	 */
	///@{
	static double getProbabilityOfAccessAttack(const QueryRisk& qr);
	static double getProbabilityOfBypassAttack(const QueryRisk& qr);
	static double getProbabilityOfDenialAttack(const QueryRisk& qr);
	static double getProbabilityOfFingerprintingAttack(const QueryRisk& qr);
	static double getProbabilityOfModificationAttack(const QueryRisk& qr);
	static double getProbabilityOfSchemaAttack(const QueryRisk& qr);
	///@}

private:
	/**
	 * Default constructor.
	 * @param numObjects The number of objects to make; this will allow
	 * concurrent access for that number of threads.
	 * @throw DescribedException Unable to open a file.
	 */
	MySqlGuardObjectContainer(int numObjects);
	
	~MySqlGuardObjectContainer();
	
	static void writeToLog(std::ofstream& log, double prob,
		const char* message);
	
	/**
	 * Locks one attack probability generator. Callees must manually unlock it!
	 * @return The number of the probability generator that was locked.
	 */
	int getLockOnProbabilityGenerator();
	
	static MySqlGuardObjectContainer* instance_;
	
	/// @TODO Rather than have locks around AttackProbabilities, have individual
	/// locks around each probability generation method.
	int numObjects_;
	int loadBalancer_;
	boost::mutex* attackProbsMutexes_;
	AttackProbabilities** attackProbs_;
	
	// Disallowed methods
	MySqlGuardObjectContainer(const MySqlGuardObjectContainer& rhs);
	MySqlGuardObjectContainer& operator=(const MySqlGuardObjectContainer& rhs);
};

#endif
