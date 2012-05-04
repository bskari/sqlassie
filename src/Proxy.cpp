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

#include "AutoPtrWithOperatorParens.hpp"
#include "Logger.hpp"
#include "Proxy.hpp"
#include "ProxyHalf.hpp"
#include "Socket.hpp"

#include <boost/thread.hpp>
#include <memory>

using boost::thread;
using std::auto_ptr;


Proxy::Proxy(
    AutoPtrWithOperatorParens<ProxyHalf> in,
    AutoPtrWithOperatorParens<ProxyHalf> out,
    auto_ptr<Socket> inSocket, auto_ptr<Socket> outSocket
) :
    in_(in),
    out_(out),
    inSocket_(inSocket),
    outSocket_(outSocket)
{
}


Proxy::Proxy(Proxy& rhs) :
    in_(rhs.in_),
    out_(rhs.out_),
    inSocket_(rhs.inSocket_),
    outSocket_(rhs.outSocket_)
{
}


Proxy::~Proxy()
{
}


void Proxy::operator()()
{
    runUntilFinished();
}


void Proxy::runUntilFinished()
{
    thread inThread(in_);
    thread outThread(out_);
    inThread.join();
    outThread.join();
    Logger::log(Logger::DEBUG) << "Client disconnected, quitting thread #"
        << boost::this_thread::get_id();
}
