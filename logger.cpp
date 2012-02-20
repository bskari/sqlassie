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

#include "MySqlLoggerListenSocket.hpp"

#include <iostream>
#include <boost/lexical_cast.hpp>

using namespace std;
using namespace boost;

int main(int argc, char* argv[])
{
	if (argc < 4)
	{
		cerr << "Usage: " << argv[0] << " listenPort MySQL-port MySQL-host" << endl;
		return -1;
	}
	const uint16_t listenPort = lexical_cast<uint16_t>(argv[1]);
	const uint16_t mySqlPort = lexical_cast<uint16_t>(argv[2]);
	MySqlLoggerListenSocket logger(listenPort, mySqlPort, argv[3]);
	logger.acceptClients();
	cout << "Exiting main" << endl;
}
