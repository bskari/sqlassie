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
#include "DescribedException.hpp"
#include "DlibProbabilities.hpp"
#include "Logger.hpp"
#include "MySqlGuardObjectContainer.hpp"
#include "nullptr.hpp"

#include <boost/thread.hpp>
#include <boost/thread/mutex.hpp>
#include <fstream>
#include <string>

using boost::lock_guard;
using boost::mutex;
using std::endl;
using std::ofstream;
using std::string;


// Static variables
MySqlGuardObjectContainer* MySqlGuardObjectContainer::instance_ = nullptr;


MySqlGuardObjectContainer::MySqlGuardObjectContainer(
    const int numObjects
) :
    numObjects_(numObjects),
    loadBalancer_(0),
    attackProbsMutexes_(new mutex[numObjects]),
    attackProbs_(new AttackProbabilities*[numObjects])
{
    for (int i = 0; i < numObjects; ++i)
    {
        try
        {
            attackProbs_[i] = new DlibProbabilities;
        }
        catch (...)
        {
            for (int j = 0; j < i; ++j)
            {
                delete attackProbs_[j];
            }
            delete [] attackProbsMutexes_;
            delete [] attackProbs_;
            throw;
        }
    }
    assert(
        numObjects > 0 &&
        numObjects <= 256 &&
        "Number of objects should match the number of hardware threads"
    );
}


MySqlGuardObjectContainer::~MySqlGuardObjectContainer()
{
    delete [] attackProbsMutexes_;
    delete [] attackProbs_;
}


void MySqlGuardObjectContainer::initialize()
{
    // Prevent race conditions between threads
    mutex m;
    lock_guard<mutex> lg(m);

    if (nullptr == instance_)
    {
        const unsigned numCores = boost::thread::hardware_concurrency();
        instance_ = new MySqlGuardObjectContainer(numCores);
    }
}


void MySqlGuardObjectContainer::logBlockedQuery(
    const string& query,
    const string& attackType,
    const double attackProbability
)
{
    Logger::log(Logger::WARN)
        << "Blocked '"
        << query
        << "' was identified as "
        << attackType
        << " attack with "
        << attackProbability
        << " probability.";
}


int MySqlGuardObjectContainer::getLockOnProbabilityGenerator()
{
    /// @TODO(bskari) Make this lock stuff exception safe
    // Try all the locks
    for (int i = 0; i < numObjects_; ++i)
    {
        if (attackProbsMutexes_[i].try_lock())
        {
            return i;
        }
    }

    // Wait on an arbitrary lock
    const int currentLoadBalancer = loadBalancer_;
    loadBalancer_ = (loadBalancer_ + 1) % numObjects_;
    attackProbsMutexes_[currentLoadBalancer].lock();
    return currentLoadBalancer;
}


double MySqlGuardObjectContainer::getProbabilityOfAccessAttack(
    const QueryRisk& qr
)
{
    assert(
        instance_ != nullptr
        && "Called MySqlGuardObjectContainer singleton without initializing"
    );
    const int lock = instance_->getLockOnProbabilityGenerator();
    const double prob =
        instance_->attackProbs_[lock]->getProbabilityOfAccessAttack(qr);
    instance_->attackProbsMutexes_[lock].unlock();
    return prob;
}


double MySqlGuardObjectContainer::getProbabilityOfBypassAttack(
    const QueryRisk& qr
)
{
    assert(
        instance_ != nullptr
        && "Called MySqlGuardObjectContainer singleton without initializing"
    );
    const int lock = instance_->getLockOnProbabilityGenerator();
    const double prob =
        instance_->attackProbs_[lock]->getProbabilityOfBypassAttack(qr);
    instance_->attackProbsMutexes_[lock].unlock();
    return prob;
}


double MySqlGuardObjectContainer::getProbabilityOfModificationAttack(
    const QueryRisk& qr
)
{
    assert(
        instance_ != nullptr
        && "Called MySqlGuardObjectContainer singleton without initializing"
    );
    const int lock = instance_->getLockOnProbabilityGenerator();
    const double prob =
        instance_->attackProbs_[lock]->getProbabilityOfModificationAttack(qr);
    instance_->attackProbsMutexes_[lock].unlock();
    return prob;
}


double MySqlGuardObjectContainer::getProbabilityOfFingerprintingAttack(
    const QueryRisk& qr
)
{
    assert(
        instance_ != nullptr
        && "Called MySqlGuardObjectContainer singleton without initializing"
    );
    const int lock = instance_->getLockOnProbabilityGenerator();
    const double prob =
        instance_->attackProbs_[lock]->
            getProbabilityOfFingerprintingAttack(qr);
    instance_->attackProbsMutexes_[lock].unlock();
    return prob;
}


double MySqlGuardObjectContainer::getProbabilityOfSchemaAttack(
    const QueryRisk& qr
)
{
    assert(
        instance_ != nullptr
        && "Called MySqlGuardObjectContainer singleton without initializing"
    );
    const int lock = instance_->getLockOnProbabilityGenerator();
    const double prob =
        instance_->attackProbs_[lock]->getProbabilityOfSchemaAttack(qr);
    instance_->attackProbsMutexes_[lock].unlock();
    return prob;
}


double MySqlGuardObjectContainer::getProbabilityOfDenialAttack(
    const QueryRisk& qr
)
{
    assert(
        instance_ != nullptr
        && "Called MySqlGuardObjectContainer singleton without initializing"
    );
    const int lock = instance_->getLockOnProbabilityGenerator();
    const double prob =
        instance_->attackProbs_[lock]->getProbabilityOfDenialAttack(qr);
    instance_->attackProbsMutexes_[lock].unlock();
    return prob;
}
