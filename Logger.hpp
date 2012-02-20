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

#ifndef LOGGER_HPP
#define LOGGER_HPP

/**
 * Singleton logger.
 * 
 * @author Brandon Skari
 * @date October 16 2011
 */

#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/thread/mutex.hpp>
#include <iostream>
#include <string>


class Logger
{
private:
	class LoggerStream;
public:
	class LogLevel;
	
	/**
	 * Initalizes the singleton instance if not done yet. The default logging
	 * level is to log messages with WARN and higher priorities.
	 */
	static void initialize(std::ostream& out = std::cout);
	
	/**
	 * Log a message. This can be then used like a normal output stream.
	 * Usage example:
	 * Logger::log(INFO) << "Forking thread";
	 * Note that this is only as thread safe as your underlying ostream object
	 * is!
	 * 
	 * @param level The log level that the message is.
	 * @return A stream object for the message.
	 */
	static LoggerStream log(const LogLevel& level);
	
	/**
	 * Sets the log level for this logger. Messages with priorities higher than
	 * the provided value will be displayed.
	 */
	static void setLevel(const int level);
	static void setLevel(const LogLevel& level);
	
	class LogLevel
	{
	public:
		LogLevel(const int level, const std::string& description) :
			level_(level),
			description_(description)
		{
		}
		const int level_;
		const std::string description_;
	};
	
	/**
	 * Predefined log levels.
	 */
	//@{
	const static LogLevel ALL;
	const static LogLevel TRACE;
	const static LogLevel DEBUG;
	const static LogLevel INFO;
	const static LogLevel WARN;
	const static LogLevel ERROR;
	const static LogLevel FATAL;
	const static LogLevel NONE;
	//@}

private:
	Logger(std::ostream& out);
	
	static Logger* instance_;
	std::ostream& out_;
	int level_;
	
	class LoggerStream
	{
	public:
		LoggerStream(std::ostream& out, const LogLevel& logLevel, const int level);
		LoggerStream(const LoggerStream& rhs);
		
		~LoggerStream();
		
		template<typename T>
		LoggerStream& operator<<(const T& object);


	private:
		std::ostream& out_;
		bool enabled_;
		boost::lock_guard<boost::mutex> guard_;
		static boost::mutex streamLock_;

		// ***** Hidden methods *****
		LoggerStream& operator=(const LoggerStream& rhs);

		// LoggerStream's destructor handles newlines, we shouldn't be using
		// endl ourselves; so declare an overload but don't define it so that
		// if we try to use endl with Logger, it won't compile.
		LoggerStream& operator<<(LoggerStream&(*myendl)(LoggerStream&));
	};
	
	// ***** Hidden methods *****
	Logger& operator=(const Logger& rhs);
};


template<typename T>
Logger::LoggerStream& Logger::LoggerStream::operator<<(const T& object)
{
	if (enabled_)
	{
		try
		{
			out_ << object;
		}
		catch (...)
		{
			// Logger should never throw
		}
	}
	return *this;
}

#endif
