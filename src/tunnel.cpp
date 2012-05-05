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

/**
 * Tunnels connections between two ports. Used for testing Socket.
 * @author Brandon Skari
 * @date November 7 2010
 */

#include "accumulator.hpp"
#include "DescribedException.hpp"
#include "Logger.hpp"
#include "nullptr.hpp"
#include "ProxyListenSocket.hpp"

#include <boost/cstdint.hpp>
#include <boost/program_options.hpp>
#include <iostream>
#include <fstream>
#include <signal.h>
#include <string>
#include <unistd.h>

using std::ifstream;
using std::cerr;
using std::cout;
using std::endl;
namespace options = boost::program_options;
using std::string;

static const int UNSPECIFIED_OPTION = -1;
static const char* DEFAULT_HOST = "127.0.0.1";
static int verbosityLevel = 0;

static void handleSignal(int signal);
static void quit();
static options::options_description getConfigurationOptions();
static options::options_description getCommandLineOptions();
static void checkOptions(const options::variables_map& opts);
static void setVerbosityLevel(const int level);

static ProxyListenSocket* pls = nullptr;


int main(int argc, char* argv[])
{
    // Instantiate the logger to avoid race conditions
    Logger::initialize();

    options::variables_map vm;
    options::options_description visibleOptions("Options");
    try
    {
        // Read command line options
        visibleOptions.add(getCommandLineOptions()).add(getConfigurationOptions());

        store(options::command_line_parser(argc, argv).options(visibleOptions).run(), vm);
        notify(vm);

        // Read options from file
        if (!vm["config"].as<string>().empty())
        {
            ifstream optionsFile(vm["config"].as<string>().c_str());
            if (optionsFile.is_open())
            {
                store(parse_config_file(optionsFile, getConfigurationOptions()), vm);
            }
            else
            {
                cerr << "Unable to open config file: " << vm["config"].as<string>() << endl;
                exit(EXIT_FAILURE);
            }
        }

        if (vm["help"].as<bool>())
        {
            cout << visibleOptions << endl;
            exit(EXIT_SUCCESS);
        }
    }
    catch (std::exception& e)
    {
        cerr << e.what() << endl;
        exit(EXIT_FAILURE);
    }

    try
    {
        checkOptions(vm);
    }
    catch (std::exception& e)
    {
        cerr << "***** " << e.what() << " *****" << endl;
        cerr << visibleOptions << endl;
        exit(EXIT_FAILURE);
    }

    switch (verbosityLevel)
    {
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

    #ifdef NDEBUG
        // Let debuggers catch exceptions so we can get backtraces
        try
    #endif
    {
        const bool useListenPort = (vm["listen-port"].as<int>() != UNSPECIFIED_OPTION);
        const bool useConnectPort = (vm["connect-port"].as<int>() != UNSPECIFIED_OPTION);

        const string connectHost = !vm["host"].as<string>().empty() ? vm["host"].as<string>() : DEFAULT_HOST;

        if (useListenPort)
        {
            Logger::log(Logger::WARN) << "Warning: Listening on a port causes a large performance penalty.";
            Logger::log(Logger::WARN) << "Listening on a domain socket (using -d) is strongly recommended.";

            const uint16_t listenPort = vm["listen-port"].as<int>();
            Logger::log(Logger::DEBUG) << "Listening on port " << listenPort;
            if (useConnectPort)
            {
                const uint16_t connectPort = vm["connect-port"].as<int>();
                Logger::log(Logger::DEBUG) << "Connecting to port " << connectPort;
                pls = new ProxyListenSocket(
                    listenPort,
                    connectPort,
                    connectHost
                );
            }
            else
            {
                const string domainSocket = vm["domain-socket"].as<string>();
                Logger::log(Logger::DEBUG) << "Connecting to socket " << domainSocket;
                pls = new ProxyListenSocket(
                    listenPort,
                    domainSocket
                );
            }
        }
        else
        {
            const string listenDomain = vm["listen-domain"].as<string>();
            Logger::log(Logger::DEBUG) << "Listening on socket " << listenDomain;
            if (useConnectPort)
            {
                const uint16_t connectPort = vm["connect-port"].as<int>();
                Logger::log(Logger::DEBUG) << "Connecting to port" << connectPort;
                pls = new ProxyListenSocket(
                    listenDomain,
                    connectPort,
                    connectHost
                );
            }
            else
            {
                const string connectDomain = vm["connect-domain"].as<string>();
                Logger::log(Logger::DEBUG) << "Connecting to socket " << connectDomain;
                pls = new ProxyListenSocket(
                    listenDomain,
                    connectDomain
                );
            }
        }
        pls->acceptClients();
    }
    #ifdef NDEBUG
        catch(std::exception& e)
        {
            Logger::log(Logger::FATAL) << "tunnel quitting after catching exception: "
                << e.what();
            quit();
        }
    #endif
}


void handleSignal(int signal)
{
    if (SIGINT == signal)
    {
        cout << "Caught signal, quitting" << endl;
        quit();
    }
}


void quit()
{
    delete pls;

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
            "help",
            options::value<bool>()->default_value(false),
            "Print help message"
        )
        (
            "config",
            options::value<string>()->default_value(""),
            "File to read configuration options from."
        );
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
            "connect-port,c",
            options::value<int>()->default_value(UNSPECIFIED_OPTION),
            "The port to connect to the MySQL server."
        )
        (
            "listen-port,l",
            options::value<int>()->default_value(UNSPECIFIED_OPTION),
            "The port to listen on for connections."
        )
        (
            "connect-socket,s",
            options::value<string>()->default_value(""),
            "The domain socket to connect to."
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
        );
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
    const bool listenSocket = !opts["listen-socket"].as<string>().empty();
    if (listenPort == listenSocket)
    {
        throw DescribedException("You must specify one method for listening");
    }

    const bool connectPort = (opts["connect-port"].as<int>() != UNSPECIFIED_OPTION);
    const bool connectSocket = !opts["connect-socket"].as<string>().empty();
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
    const bool host = !opts["host"].as<string>().empty();
    if (host && !connectPort)
    {
        throw DescribedException("Host is only valid when connecting using ports");
    }
}
