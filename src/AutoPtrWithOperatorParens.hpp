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

#ifndef SRC_AUTOPTRWITHOPERATORPARENS_HPP_
#define SRC_AUTOPTRWITHOPERATORPARENS_HPP_

#include "nullptr.hpp"

#include <memory>

/**
 * My own implementation of auto_ptr that includes operator() and calls the
 * object's operator().
 * When Boost creates threads, it uses the copy constructor of an object to make
 * several copies of the object before it eventually calls the object's
 * operator(). If a reference to a derived object is sent as a base class, then
 * the base class's copy constructor will be called and the object will be
 * sliced. This is an attempt at preventing that problem by allowing an auto_ptr
 * to be passed to Boost thread constructors.
 */

template <class Type>
class AutoPtrWithOperatorParens
{
public:
    /**
     * Default constructor.
     * @param ptr The pointer to own and control.
     */
    explicit AutoPtrWithOperatorParens(Type* ptr = nullptr) throw();

    /**
     * Copy constructor.
     * @param rhs The auto pointer to take the reference from.
     */
    AutoPtrWithOperatorParens(AutoPtrWithOperatorParens<Type>& rhs) throw();

    ~AutoPtrWithOperatorParens() throw();

    // Reimplemented methods, same as in std::auto_ptr
    Type* get() const throw();
    Type& operator*() const throw();
    Type& operator->() const throw();
    Type& operator=(AutoPtrWithOperatorParens<Type>& rhs) throw();
    Type* release() throw();
    void reset(Type* ptr = nullptr) throw();

    void operator()();

private:
    Type* object_;
};


template <class Type>
AutoPtrWithOperatorParens<Type>::AutoPtrWithOperatorParens(Type* ptr) throw() :
    object_(ptr)
{
}


template <class Type>
AutoPtrWithOperatorParens<Type>::AutoPtrWithOperatorParens(
    AutoPtrWithOperatorParens<Type> &rhs) throw() :
    object_(rhs.object_)
{
    rhs.object_ = nullptr;
}


template <class Type>
AutoPtrWithOperatorParens<Type>::~AutoPtrWithOperatorParens() throw()
{
    delete object_;
}


template <class Type>
Type* AutoPtrWithOperatorParens<Type>::get() const throw()
{
    return object_;
}


template <class Type>
Type& AutoPtrWithOperatorParens<Type>::operator*() const throw()
{
    return *object_;
}


template <class Type>
Type& AutoPtrWithOperatorParens<Type>::operator->() const throw()
{
    return *object_;
}


template <class Type>
Type& AutoPtrWithOperatorParens<Type>::operator=(AutoPtrWithOperatorParens<Type>& rhs) throw()
{
    object_ = rhs.object_;
    rhs.object_ = nullptr;
}


template <class Type>
Type* AutoPtrWithOperatorParens<Type>::release() throw()
{
    object_ = nullptr;
}


template <class Type>
void AutoPtrWithOperatorParens<Type>::reset(Type* ptr) throw()
{
    delete object_;
    object_ = ptr;
}


template <class Type>
void AutoPtrWithOperatorParens<Type>::operator()()
{
    object_->operator()();
}
#endif  // SRC_AUTOPTRWITHOPERATORPARENS_HPP_
