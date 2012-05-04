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

#include "Logger.hpp"
#include "nullptr.hpp"

#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/thread/mutex.hpp>
#include <cassert>
#include <ostream>
#include <limits>
#include <string>

using boost::adopt_lock_t;
using boost::mutex;
using boost::lock_guard;
using boost::posix_time::ptime;
using boost::posix_time::second_clock;
using std::endl;
using std::numeric_limits;
using std::ostream;
using std::string;

// Static members
const Logger::LogLevel Logger::ALL(numeric_limits<int>::min(), "ALL  ");
const Logger::LogLevel Logger::TRACE(0, "TRACE");
const Logger::LogLevel Logger::DEBUG(100, "DEBUG");
const Logger::LogLevel Logger::INFO(200, "INFO ");
const Logger::LogLevel Logger::WARN(300, "WARN ");
const Logger::LogLevel Logger::ERROR(400, "ERROR");
const Logger::LogLevel Logger::FATAL(500, "FATAL");
const Logger::LogLevel Logger::NONE(numeric_limits<int>::max(), "NONE ");
Logger* Logger::instance_ = nullptr;
mutex Logger::LoggerStream::streamLock_;


Logger::Logger(ostream& out) :
    out_(out),
    level_(WARN.level_)
{
}


void Logger::initialize(ostream& out)
{
    // Prevent race conditions between threads
    mutex m;
    lock_guard<mutex> lg(m);

    if (nullptr == instance_)
    {
        instance_ = new Logger(out);
    }
}


Logger::LoggerStream Logger::log(const LogLevel& logLevelObject)
{
    assert(instance_ != nullptr && "Called Logger singleton without initializing");
    return LoggerStream(instance_->out_, logLevelObject, instance_->level_);
}


void Logger::setLevel(const int level)
{
    assert(instance_ != nullptr && "Called Logger singleton without initializing");
    instance_->level_ = level;
}


void Logger::setLevel(const LogLevel& level)
{
    assert(instance_ != nullptr && "Called Logger singleton without initializing");
    instance_->level_ = level.level_;
}


Logger::LoggerStream::LoggerStream(ostream& out, const LogLevel& logLevel, const int level) :
    out_(out),
    enabled_(logLevel.level_ >= level),
    guard_(streamLock_)
{
    if (enabled_)
    {
        try
        {
            ptime now(second_clock::local_time());
            out_ << now << ' ' << logLevel.description_ << ' ';
        }
        catch (...)
        {
            // Logger should never throw
        }
    }
}


Logger::LoggerStream::LoggerStream(const Logger::LoggerStream& rhs) :
    out_(rhs.out_),
    enabled_(rhs.enabled_),
    guard_(streamLock_, adopt_lock_t()) // Take ownership of the lock
{
}


Logger::LoggerStream::~LoggerStream()
{
    if (enabled_)
    {
        try
        {
            out_ << endl;
        }
        catch (...)
        {
            // Logger should never throw
        }
    }
}
