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

#ifndef ATTACK_PROBABILITIES_HPP
#define ATTACK_PROBABILITIES_HPP

#include "QueryRisk.hpp"

/**
 * Class interface with pure virtual methods to compute the probability of
 * attack given a particular query risk assessment.
 * @author Brandon Skari
 * @date January 5 2011
 */

class AttackProbabilities
{
public:
	/**
	 * Returns the probability of a given type of attack.
	 */
	///@{
	virtual double getProbabilityOfAccessAttack(const QueryRisk& qr) = 0;
	virtual double getProbabilityOfBypassAttack(const QueryRisk& qr) = 0;
	virtual double getProbabilityOfModificationAttack(const QueryRisk& qr) = 0;
	virtual double getProbabilityOfFingerprintingAttack(const QueryRisk& qr) = 0;
	virtual double getProbabilityOfSchemaAttack(const QueryRisk& qr) = 0;
	virtual double getProbabilityOfDenialAttack(const QueryRisk& qr) = 0;
	///@}
	
	virtual ~AttackProbabilities();
};
#endif
