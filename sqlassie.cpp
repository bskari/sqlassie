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

#include "accumulator.hpp"
#include "DescribedException.hpp"
#include "getpass.h"
#include "Logger.hpp"
#include "MySqlGuardListenSocket.hpp"
#include "MySqlGuardObjectContainer.hpp"
#include "nullptr.hpp"
#include "QueryWhitelist.hpp"
#include "version.h"

#include <boost/cstdint.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/program_options.hpp>
#include <exception>
#include <fstream>
#include <iostream>
#include <signal.h>
#include <string>
#include <unistd.h>

using namespace std;
using namespace boost;
namespace options = boost::program_options;

static const int UNSPECIFIED_OPTION = -1;
static const int DEFAULT_CONNECT_PORT = 3306;
static const int DEFAULT_LISTEN_PORT = 3307;
static const char* DEFAULT_CONFIG_FILE = "sqlassie.conf";
static const char* DEFAULT_HOST = "127.0.0.1";
static const char* PARSER_WHITELIST_OPTION = "parser-query-whitelist-file";
static const char* BLOCKED_WHITELIST_OPTION = "blocked-query-whitelist-file";

static MySqlGuardListenSocket* mysqlGuard = nullptr;
static int verbosityLevel = 0;

static void handleSignal(int signal);
static void quit();
static options::options_description getCommandLineOptions();
static options::options_description getConfigurationOptions();
static options::options_description getFileOptions();
static void checkOptions(const options::variables_map& opts);
static void setVerbosityLevel(const int level);


int main(int argc, char* argv[])
{
	// Instantiate singleton classes
	Logger::initialize();
	MySqlGuardObjectContainer::initialize();
	
	options::variables_map vm;
	options::options_description visibleOptions("Options");
	try
	{
		// Read command line options
		visibleOptions.add(getCommandLineOptions());
		visibleOptions.add(getConfigurationOptions());

		store(options::command_line_parser(argc, argv).options(visibleOptions).run(), vm);
		notify(vm);
		
		// Read options from file
		ifstream optionsFile(vm["config"].as<string>().c_str());
		if (optionsFile.is_open())
		{
			Logger::log(Logger::INFO) << "Reading configuration from file " << vm["config"].as<string>();
			options::options_description fileOptions("File options");
			fileOptions.add(getConfigurationOptions());
			fileOptions.add(getFileOptions());
			store(parse_config_file(optionsFile, fileOptions), vm);
		}
		// Ignore unable to find the file if it's set to default
		else if (vm["config"].as<string>() != DEFAULT_CONFIG_FILE)
		{
			cerr << "Unable to open config file: " << vm["config"].as<string>() << endl;
			exit(EXIT_FAILURE);
		}

		if (vm.count("help"))
		{
			cout << visibleOptions << endl;
			exit(EXIT_SUCCESS);
		}
		if (vm.count("version"))
		{
			cout << sqlassieName() << ' ' << sqlassieVersion() << endl;
			cout << sqlassieCopyright() << endl;
			cout << sqlassieShortLicense() << endl;
			exit(EXIT_SUCCESS);
		}

		checkOptions(vm);
	}
	catch (std::exception& e)
	{
		const int error_len = strlen(e.what());
		cerr << '\t';
		for (int i = 0; i < error_len; ++i)
		{
			cerr << '*';
		}
		cerr << endl;

		cerr << '\t' << e.what() << endl;

		cerr << '\t';
		for (int i = 0; i < error_len; ++i)
		{
			cerr << '*';
		}
		cerr << endl;

		cerr << visibleOptions << endl;
		exit(EXIT_FAILURE);
	}

	if (vm["quiet"].as<bool>())
	{
		verbosityLevel = -1;
	}
	switch (verbosityLevel)
	{
	case -1:
		Logger::setLevel(Logger::FATAL);
		break;
	case 0:
		Logger::setLevel(Logger::WARN);
		break;
	case 1:
		Logger::setLevel(Logger::INFO);
		break;
	case 2:
		Logger::setLevel(Logger::DEBUG);
		break;
	case 3:
		Logger::setLevel(Logger::TRACE);
		break;
	default:
		Logger::setLevel(Logger::ALL);
		break;
	}
	
	// Override logging level in debug builds
	#ifndef NDEBUG
		cout << "This is a testing/debug build of SQLassie." << endl;
		cout << "Log level is being set to ALL." << endl;
		Logger::setLevel(Logger::ALL);
	#endif
	
	// Register signal handler
	signal(SIGINT, handleSignal);

	// Set up whitelists
	const string* whitelistFilenames[] = {nullptr, nullptr};
	const char* const optionNames[] = {
		PARSER_WHITELIST_OPTION,
		BLOCKED_WHITELIST_OPTION
	};
	assert(
		sizeof(whitelistFilenames) / sizeof(whitelistFilenames[0]) ==
		sizeof(optionNames) / sizeof(optionNames[0])
	);
	for (
		size_t i = 0; 
		i < sizeof(whitelistFilenames) / sizeof(whitelistFilenames[0]);
		++i
	)
	{
		if (!vm[optionNames[i]].as<string>().empty())
		{
			whitelistFilenames[i] = new string(
				vm[optionNames[i]].as<string>()
			);
		}
	}
	QueryWhitelist::initialize(whitelistFilenames[0], whitelistFilenames[1]);
	for (
		size_t i = 0; 
		i < sizeof(whitelistFilenames) / sizeof(whitelistFilenames[0]);
		++i
	)
	{
		delete whitelistFilenames[i];
	}
	
	#ifdef NDEBUG
		// Let debuggers catch exceptions so we can get backtraces
		try
	#endif
	{
		const bool useListenPort = (vm["listen-port"].as<int>() != UNSPECIFIED_OPTION);
		const bool useConnectPort = (vm["connect-port"].as<int>() != UNSPECIFIED_OPTION);
		
		const string connectHost = (vm["host"].as<string>() != "") ? vm["host"].as<string>() : DEFAULT_HOST;

		const string username = vm["user"].as<string>();
		const string password = vm["password"].as<string>();
		
		if (useListenPort)
		{
			Logger::log(Logger::WARN) << "Listening on a port causes a large performance penalty.";
			Logger::log(Logger::WARN) << "Listening on a domain socket (using -d) is strongly recommended.";
			
			const uint16_t listenPort = vm["listen-port"].as<int>();
			Logger::log(Logger::DEBUG) << "Listening on port " << listenPort;
			if (useConnectPort)
			{
				const uint16_t connectPort = vm["connect-port"].as<int>();
				Logger::log(Logger::DEBUG) << "Connecting to port " << connectPort;
				mysqlGuard = new MySqlGuardListenSocket(listenPort,
					connectPort, connectHost, username, password);
			}
			else
			{
				const string domainSocket(vm["connect-socket"].as<string>());
				Logger::log(Logger::DEBUG) << "Connecting to socket " << domainSocket;
				mysqlGuard = new MySqlGuardListenSocket(listenPort,
					domainSocket, username, password);
			}
		}
		else
		{
			const string listenDomain(vm["listen-socket"].as<string>());
			Logger::log(Logger::DEBUG) << "Listening on socket " << listenDomain;
			if (useConnectPort)
			{
				const uint16_t connectPort = vm["connect-port"].as<int>();
				Logger::log(Logger::DEBUG) << "Connecting to port" << connectPort;
				mysqlGuard = new MySqlGuardListenSocket(listenDomain,
					connectPort, connectHost, username, password);
			}
			else
			{
				const string connectDomain(vm["connect-socket"].as<string>());
				Logger::log(Logger::DEBUG) << "Connecting to socket " << connectDomain;
				mysqlGuard = new MySqlGuardListenSocket(listenDomain,
					connectDomain, username, password);
			}
		}
		mysqlGuard->acceptClients();
	}
	#ifdef NDEBUG
		catch(std::exception& e)
		{
			Logger::log(Logger::FATAL) << "SQLassie quitting after catching exception: "
				<< e.what();
			quit();
		}
	#endif
}


/**
 * Signal handler that tries to gracefully clean up before exiting.
 */
void handleSignal(int signal)
{
	if (SIGINT == signal)
	{
		cout << "Caught signal, quitting" << endl;
		quit();
	}
}


/**
 * Tries to gracefully clean up sockets, memory, and other resources.
 */
void quit()
{
	delete mysqlGuard;
	
	// Give the socket time to close?
	// It didn't close one time before quitting... maybe this will fix it
	sleep(1);
	
	exit(EXIT_SUCCESS);
}


/**
 * Command line only options.
 */
options::options_description getCommandLineOptions()
{
	options::options_description cli("Command line options");
	cli.add_options()
		(
			"version",
			"Print version string"
		)
		(
			"help",
			"Print help message"
		)
		(
			"config",
			options::value<string>()->default_value(DEFAULT_CONFIG_FILE),
			"File to read configuration options from."
		)
		;
	return cli;
}


/**
 * Notifier function for multiple verbose flags.
 */
void setVerbosityLevel(const int level)
{
	verbosityLevel = level;
}


/**
 * Options that can be configured from either a file, or from the command line.
 */
options::options_description getConfigurationOptions()
{
	options::options_description configuration("Configuration options");
	configuration.add_options()
		(
			"verbose,v",
			accumulator<int>()->implicit_value(1)->notifier(setVerbosityLevel),
			"Print extra information. Add more for more information."
		)
		(
			"quiet,q",
			options::value<bool>()->default_value(false),
			"Suppress warnings."
		)
		(
			"connect-port,c",
			// Use int instead of uint16_t so that I can default to an
			// unspecified (and illegal uint16_t) value
			options::value<int>()->default_value(UNSPECIFIED_OPTION),
			"The port to connect to the MySQL server."
		)
		(
			"listen-port,l",
			// Use int instead of uint16_t so that I can default to an
			// unspecified (and illegal uint16_t) value
			options::value<int>()->default_value(UNSPECIFIED_OPTION),
			"The port to listen on for connections."
		)
		(
			"connect-socket,s",
			options::value<string>()->default_value(""),
			"The domain socket to connect to for the server."
		)
		(
			"listen-socket",
			options::value<string>()->default_value(""),
			"The domain socket to listen on for connections."
		)
		(
			"host,h",
			options::value<string>()->default_value(""),
			"The host to connect to."
		)
		(
			"user,u",
			options::value<string>()->default_value(""),
			"The username to use when reading MySQL user permissions."
		)
		(
			"password,p",
			options::value<string>()->default_value(""),
			"The password to use when reading MySQL user permissions."
		)
	;
	return configuration;
}


/**
 * Options that can be configured from a file.
 */
options::options_description getFileOptions()
{
	options::options_description configuration("File options");
	configuration.add_options()
		(
		 	BLOCKED_WHITELIST_OPTION,
			options::value<string>()->default_value(""),
			"A file containing known safe queries that should not be blocked."
		)
		(
			PARSER_WHITELIST_OPTION,
			options::value<string>()->default_value(""),
			"A file containing queries that SQLassie has failed to parse but should be forwarded anyway."
		)
	;
	return configuration;
}




/**
 * Checks to make sure all the parameters are in the expected range, and no
 * conflicting paramters are specified.
 * @throw DescribedException Error in parsing the command line arguments.
 */
void checkOptions(const options::variables_map& opts)
{
	// The user should have exactly one of each of these pairs
	const bool listenPort = (opts["listen-port"].as<int>() != UNSPECIFIED_OPTION);
	const bool listenSocket = (opts["listen-socket"].as<string>() != "");
	if (listenPort == listenSocket)
	{
		throw DescribedException("You must specify one method for listening");
	}
	
	const bool connectPort = (opts["connect-port"].as<int>() != UNSPECIFIED_OPTION);
	const bool connectSocket = (opts["connect-socket"].as<string>() != "");
	if (connectPort == connectSocket)
	{
		throw DescribedException("You must specify one method for connecting");
	}
	
	// Make sure that port numbers are in a valid range
	if (listenPort)
	{
		const int portNumber = opts["listen-port"].as<int>();
		if (portNumber < 1 || portNumber > 65535)
		{
			throw DescribedException("Port number is out of range; valid values are 1-65535");
		}
	}
	if (connectPort)
	{
		const int portNumber = opts["connect-port"].as<int>();
		if (portNumber < 1 || portNumber > 65535)
		{
			throw DescribedException("Port number is out of range; valid values are 1-65535");
		}
	}
	
	// Host is only valid if connecting to a port
	const bool host = (opts["host"].as<string>() != "");
	if (host && !connectPort)
	{
		throw DescribedException("Host is only valid when connecting using ports");
	}
	
	// Password is only valid if a user is specified
	const bool user = (opts["user"].as<string>() != "");
	const bool password = (opts["password"].as<string>() != "");
	if (password && !user)
	{
		throw DescribedException("Password can only be used if a username is specified");
	}

	// Quiet can't be specified with verbose
	if (opts["quiet"].as<bool>() && verbosityLevel > 0)
	{
		throw DescribedException("Quiet can only be used without verbose options");
	}
}
