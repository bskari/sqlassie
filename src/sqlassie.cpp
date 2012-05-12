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
#include "Logger.hpp"
#include "MySqlGuardListenSocket.hpp"
#include "MySqlGuardObjectContainer.hpp"
#include "MySqlLoginCheck.hpp"
#include "nullptr.hpp"
#include "QueryWhitelist.hpp"
#include "SensitiveNameChecker.hpp"
#include "version.h"

#include <boost/bind.hpp>
#include <boost/cstdint.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/program_options.hpp>
#include <exception>
#include <fstream>
#include <iostream>
#include <signal.h>
#include <string>
#include <unistd.h>
#include <utility>

using boost::bind;
using boost::lexical_cast;
namespace options = boost::program_options;
using std::cerr;
using std::cout;
using std::endl;
using std::exception;
using std::ifstream;
using std::string;
using std::pair;

static const int UNSPECIFIED_OPTION = -1;
static const int DEFAULT_CONNECT_PORT = 3306;
static const int DEFAULT_LISTEN_PORT = 3307;
static const char* DEFAULT_CONFIG_FILE = "sqlassie.conf";
static const char* DEFAULT_HOST = "127.0.0.1";
static const char* PARSER_WHITELIST_OPTION = "parser-query-whitelist-file";
static const char* BLOCKED_WHITELIST_OPTION = "blocked-query-whitelist-file";
static const char* PASSWORD_REGEX = "password-regex";
static const char* PASSWORD_SUBSTRING = "password-substring";
static const char* USER_REGEX = "user-regex";
static const char* USER_SUBSTRING = "user-substring";

static MySqlGuardListenSocket* mysqlGuard = nullptr;
static int verbosityLevel = 0;

static void handleSignal(int signal);
static void quit();
static options::options_description getCommandLineOptions();
static options::options_description getConfigurationOptions();
static options::options_description getFileOptions();
static bool optionsAreValid(
    const options::variables_map& commandLineVm,
    const options::variables_map& fileVm,
    string* const error
);
static void setVerbosityLevel(const int level);
static void printErrorAndUsage(
    const std::string& error,
    const options::options_description& visibleOptions
);
static const options::variable_value& getOption(
    const string& option,
    const options::variables_map& vm1,
    const options::variables_map& vm2
);
static void setupOptions(
    const options::variables_map& commandLineVm,
    const options::variables_map& fileVm
);


int main(int argc, char* argv[])
{
    // Instantiate singleton classes
    Logger::initialize();
    MySqlGuardObjectContainer::initialize();
    SensitiveNameChecker::initialize();

    options::variables_map commandLineVm;
    options::variables_map fileVm;
    options::options_description visibleOptions("Options");
    try
    {
        // Read command line options
        visibleOptions.add(getCommandLineOptions());
        visibleOptions.add(getConfigurationOptions());

        store(
            options::command_line_parser(
                argc,
                argv
            ).options(visibleOptions).run(),
            commandLineVm
        );
        // Notify any functions for user-specified notify functions and store
        // the options into regular variables, if needed
        notify(commandLineVm);

        // Read options from file
        ifstream optionsFile(commandLineVm["config"].as<string>().c_str());
        if (optionsFile.is_open())
        {
            Logger::log(Logger::INFO)
                << "Reading configuration from file "
                << commandLineVm["config"].as<string>();
            options::options_description fileOptions("File options");
            fileOptions.add(getConfigurationOptions());
            fileOptions.add(getFileOptions());
            store(parse_config_file(optionsFile, fileOptions), fileVm);
            // Notify any functions for user-specified notify functions and
            // store the options into regular variables, if needed
            notify(fileVm);
        }
        // Ignore unable to find the file if it's set to default
        else if (commandLineVm["config"].as<string>() != DEFAULT_CONFIG_FILE)
        {
            cerr << "Unable to open config file: "
                << commandLineVm["config"].as<string>()
                << endl;
            exit(EXIT_FAILURE);
        }

        if (commandLineVm.count("help"))
        {
            cout << visibleOptions << endl;
            exit(EXIT_SUCCESS);
        }
        if (commandLineVm.count("version"))
        {
            cout << sqlassieName() << ' ' << sqlassieVersion() << '\n'
                << sqlassieCopyright() << '\n'
                << sqlassieShortLicense() << endl;
            exit(EXIT_SUCCESS);
        }
    }
    catch (std::exception& e)
    {
        printErrorAndUsage(string(e.what()), visibleOptions);
        exit(EXIT_FAILURE);
    }

    string error;
    if(!optionsAreValid(commandLineVm, fileVm, &error))
    {
        printErrorAndUsage(error, visibleOptions);
        exit(EXIT_FAILURE);
    }

    // Use the parameters
    cout << "Setting options" << endl;
    setupOptions(commandLineVm, fileVm);

    // Override logging level in debug builds
    #ifndef NDEBUG
        Logger::setLevel(Logger::ALL);
        Logger::log(Logger::INFO)
            << "This is a testing/debug build of SQLassie";
        Logger::log(Logger::INFO) << "Log level is being set to ALL";
    #endif

    // Register signal handler
    signal(SIGINT, handleSignal);

    #ifdef NDEBUG
        // Let debuggers catch exceptions so we can get backtraces
        try
    #endif
    {
        const bool useListenPort = (
            !getOption(
                "listen-port",
                commandLineVm,
                fileVm
            ).defaulted()
        );
        const bool useConnectPort = (
            !getOption(
                "connect-port",
                commandLineVm,
                fileVm
            ).defaulted()
        );

        const string connectHost = (
            getOption("host", commandLineVm, fileVm).defaulted()
            ? DEFAULT_HOST
            : getOption("host", commandLineVm, fileVm).as<string>()
        );

        const uint16_t listenPort = getOption(
            "listen-port",
            commandLineVm,
            fileVm
        ).as<int>();
        const uint16_t connectPort = getOption(
            "connect-port",
            commandLineVm,
            fileVm
        ).as<int>();
        const string domainSocket(
            getOption(
                "connect-socket",
                commandLineVm,
                fileVm
            ).as<string>()
        );
        const string listenDomain(
            getOption(
                "listen-socket",
                commandLineVm,
                fileVm
            ).as<string>()
        );

        if (useConnectPort)
        {
            Logger::log(Logger::DEBUG)
                << "Connecting to port "
                << connectPort
                << " at "
                << connectHost;
            if (useListenPort)
            {
                Logger::log(Logger::DEBUG)
                    << "Listening on port "
                    << listenPort;
                mysqlGuard = new MySqlGuardListenSocket(
                    listenPort,
                    connectPort,
                    connectHost
                );
            }
            else
            {
                Logger::log(Logger::DEBUG)
                    << "Listening on socket "
                    << listenDomain;
                mysqlGuard = new MySqlGuardListenSocket(
                    listenPort,
                    domainSocket
                );
            }
        }
        else
        {
            Logger::log(Logger::DEBUG)
                << "Connecting to socket "
                << domainSocket;
            if (useListenPort)
            {
                Logger::log(Logger::DEBUG)
                    << "Listening on port "
                    << listenPort;
                mysqlGuard = new MySqlGuardListenSocket(
                    listenPort,
                    domainSocket
                );
            }
            else
            {
                Logger::log(Logger::DEBUG)
                    << "Listening on socket "
                    << listenDomain;
                mysqlGuard = new MySqlGuardListenSocket(
                    listenDomain,
                    domainSocket
                );
            }
        }
        mysqlGuard->acceptClients();
    }
    #ifdef NDEBUG
        catch(std::exception& e)
        {
            Logger::log(Logger::FATAL)
                << "SQLassie quitting after catching exception: "
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
        );
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
            "A file containing queries that SQLassie has failed to parse but should be forwarded anyway."  // NOLINT(whitespace/line_length)
        )
        (
            PASSWORD_REGEX,
            options::value<string>()->default_value(""),
"SQLassie uses this to determine which SQL table field names should be considered passwords. Any field name matching this Perl style regular expression will be considered a password field."  // NOLINT(whitespace/line_length)
        )
        (
            PASSWORD_SUBSTRING,
            options::value<string>()->default_value(""),
            "SQLassie uses this to determine which SQL table field names should be considered passwords. Any field name containing this word will be considered a password field."  // NOLINT(whitespace/line_length)
        )
        (
            USER_REGEX,
            options::value<string>()->default_value(""),
            "SQLassie uses this to determine which SQL table names should be considered user tables. Any table name matching this Perl style regular expression will be considered a user table."  // NOLINT(whitespace/line_length)
        )
        (
            USER_SUBSTRING,
            options::value<string>()->default_value(""),
            "SQLassie uses this to determine which SQL table names should be considered user tables. Any table name containing this word will be considered a user table."  // NOLINT(whitespace/line_length)
        );
    return configuration;
}


/**
 * Checks to make sure all the parameters are in the expected range, and no
 * conflicting paramters are specified. Command line options will override
 * options specified in the configuration file.
 * @param commandLineVm Variables from the command line.
 * @param fileVm Variables from the configuration file.
 */
bool optionsAreValid(
    const options::variables_map& commandLineVm,
    const options::variables_map& fileVm,
    string* error
)
{
    const bool clListenPort = !commandLineVm["listen-port"].defaulted();
    const bool fListenPort = !fileVm["listen-port"].defaulted();
    const bool clListenSocket = !commandLineVm["listen-socket"].defaulted();
    const bool fListenSocket = !fileVm["listen-socket"].defaulted();
    // The user needs to specify one way to connect, but command line options
    // override anything from the file
    if (
        (clListenPort && clListenSocket)
        || (!clListenPort && !clListenSocket && !fListenPort && !fListenSocket)
    )
    {
        *error = "You must specify one method for listening";
        return false;
    }

    const bool clConnectPort = !commandLineVm["connect-port"].defaulted();
    const bool fConnectPort = !fileVm["connect-port"].defaulted();
    const bool clConnectSocket = !commandLineVm["connect-socket"].defaulted();
    const bool fConnectSocket = !fileVm["connect-socket"].defaulted();
    if (
        (clConnectPort && clConnectSocket)
        || (
            !clConnectPort
            && !clConnectSocket
            && !fConnectPort
            && !fConnectSocket
        )
    )
    {
        *error = "You must specify one method for connecting";
        return false;
    }

    // Make sure that port numbers are in a valid range
    if (clListenPort || fListenPort)
    {
        const options::variables_map& vm =
            (clListenPort ? commandLineVm : fileVm);
        const int portNumber = vm["listen-port"].as<int>();
        if (portNumber < 1 || portNumber > 65535)
        {
            *error = "Port number (";
            *error += boost::lexical_cast<string>(portNumber);
            *error += ") is out of range; valid values are 1-65535";
            return false;
        }
    }
    const bool connectPort = clConnectPort || fConnectPort;
    if (connectPort)
    {
        const options::variables_map& vm =
            (clConnectPort ? commandLineVm : fileVm);
        const int portNumber = vm["connect-port"].as<int>();
        if (portNumber < 1 || portNumber > 65535)
        {
            *error = "Port number (";
            *error += boost::lexical_cast<string>(portNumber);
            *error += ") is out of range; valid values are 1-65535";
            return false;
        }
    }

    // Host is only valid if connecting to a port
    const bool clHost = (commandLineVm["host"].as<string>() != "");
    const bool fHost = (fileVm["host"].as<string>() != "");
    const bool host = clHost || fHost;
    if (host && !connectPort)
    {
        *error = "Host is only valid when connecting using ports";
        return false;
    }

    // Password is only valid if a user is specified
    const bool clUser = (commandLineVm["user"].as<string>() != "");
    const bool fUser = (fileVm["user"].as<string>() != "");
    const bool user = clUser || fUser;
    const bool clPassword = (commandLineVm["password"].as<string>() != "");
    const bool fPassword = (fileVm["password"].as<string>() != "");
    const bool password = clPassword || fPassword;
    if (password && !user)
    {
        *error = "Password can only be used if a username is specified";
        return false;
    }

    // Quiet can't be specified with verbose
    const bool clQuiet = commandLineVm["quiet"].as<bool>();
    const bool fQuiet = fileVm["quiet"].as<bool>();
    const bool quiet = clQuiet || fQuiet;
    if (quiet && verbosityLevel > 0)
    {
        *error = "Quiet can only be used without verbose options";
        return false;
    }

    // Only specify one of password/user substring or regex
    const bool pwSubstr = !fileVm[PASSWORD_SUBSTRING].as<string>().empty();
    const bool pwRegex = !fileVm[PASSWORD_REGEX].as<string>().empty();
    if (pwSubstr == pwRegex)
    {
        *error = "You must specify either a password field word or regex";
        return false;
    }
    const bool userSubstr = !fileVm[USER_SUBSTRING].as<string>().empty();
    const bool userRegex = !fileVm[USER_REGEX].as<string>().empty();
    if (userSubstr == userRegex)
    {
        *error = "You must specify either a user table word or regex";
        return false;
    }

    return true;
}


/**
 * Prepares and sets up the SQLassie config from the options.
 */
void setupOptions(
    const options::variables_map& commandLineVm,
    const options::variables_map& fileVm
)
{
    // Set the logging level
    if (getOption("quiet", commandLineVm, fileVm).as<bool>())
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

    cout << "whitelists" << endl;
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
        if (
            !getOption(
                optionNames[i],
                commandLineVm,
                fileVm
            ).as<string>().empty()
        )
        {
            whitelistFilenames[i] = new string(
                getOption(optionNames[i], commandLineVm, fileVm).as<string>()
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

    // Set the sensitive tables and fields
    cout << "sensitive" << endl;
    typedef pair<
        const char*,
        boost::function<void (const string&)>
    > optionAndSetter;
    SensitiveNameChecker& ref = SensitiveNameChecker::get();
    SensitiveNameChecker* inst = &ref;

    boost::function<void (const string&)> test(
        boost::bind(
            &SensitiveNameChecker::setPasswordRegex,
            inst,
            _1
        )
    );

    optionAndSetter sensitiveNames[] = {
        optionAndSetter(
            PASSWORD_REGEX,
            boost::bind(
                &SensitiveNameChecker::setPasswordRegex,
                inst,
                _1
            )
        ),
        optionAndSetter(
            PASSWORD_SUBSTRING,
            boost::bind(
                &SensitiveNameChecker::setPasswordSubstring,
                inst,
                _1
            )
        ),
        optionAndSetter(
            USER_REGEX,
            boost::bind(
                &SensitiveNameChecker::setUserRegex,
                inst,
                _1
            )
        ),
        optionAndSetter(
            USER_SUBSTRING,
            boost::bind(
                &SensitiveNameChecker::setUserSubstring,
                inst,
                _1
            )
        )
    };
    for (
        size_t i = 0;
        i < sizeof(sensitiveNames) / sizeof(sensitiveNames[0]);
        ++i
    )
    {
        const char* const optionName = sensitiveNames[i].first;
        boost::function<void (const string&)> setter = sensitiveNames[i].second;
        const string& option = getOption(
            optionName,
            commandLineVm,
            fileVm
        ).as<string>();
        if (!option.empty())
        {
            setter(option);
        }
    }

    // Set up the login check
    cout << "Login" << endl;
    const string password(
        getOption("password", commandLineVm, fileVm).as<string>()
    );
    const string user(getOption("user", commandLineVm, fileVm).as<string>());
    const string host(getOption("host", commandLineVm, fileVm).as<string>());
    const string socket(
        getOption("connect-socket", commandLineVm, fileVm).as<string>()
    );
    if (!host.empty())
    {
        const uint16_t port(
            getOption("connect-port", commandLineVm, fileVm).as<uint16_t>()
        );
        MySqlLoginCheck::initialize(user, password, host, port);
    }
    else
    {
        MySqlLoginCheck::initialize(user, password, socket);
    }
}


void printErrorAndUsage(
    const std::string& error,
    const options::options_description& visibleOptions
)
{
    const int error_len = error.size();
    cerr << '\t';
    for (int i = 0; i < error_len; ++i)
    {
        cerr << '*';
    }
    cerr << endl;

    cerr << '\t' << error << endl;

    cerr << '\t';
    for (int i = 0; i < error_len; ++i)
    {
        cerr << '*';
    }
    cerr << endl;

    cerr << visibleOptions << endl;
}


/**
 * Returns the correct variable_map for an option, where the first
 * variable_map overrides the second. So if an option is specified in both
 * maps, the first map is returned; if the option is only in the second, the
 * second is returned. If the option is in neither, the first is returned.
 */
const options::variable_value& getOption(
    const string& option,
    const options::variables_map& vm1,
    const options::variables_map& vm2
)
{
    const options::variable_value& v1 = vm1[option];
    const options::variable_value& v2 = vm2[option];
    if (!v1.empty() && !v1.defaulted())
    {
        return v1;
    }
    return v2;
}
