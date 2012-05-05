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

#ifndef SRC_LRUCACHE_HPP_
#define SRC_LRUCACHE_HPP_

#include <boost/bimap.hpp>
#include <boost/bimap/list_of.hpp>
#include <boost/bimap/unordered_set_of.hpp>
#include <boost/function.hpp>
#include <cassert>

/**
 * Implementation of a least recently used cache. Based on the description
 * by Tim Day, from timday.bitbucket.org/lru.html.
 * @author Brandon Skari
 * @date January 28 2012
 */

template <typename KeyType, typename ValueType>
class LruCache
{
public:
    /**
     * Default constructor.
     * @param func Function to compute values for requested uncached keys.
     * @param size The number of key-value pairs to store in the cache.
     */
    LruCache(
        const boost::function<ValueType(const KeyType&)>& func,
        const size_t size
    );

    /**
     * Access values for the type key. Use operator() instead of operator[]
     * here so that users can't override the values assigned to keys.
     */
    ValueType operator()(const KeyType& key);

private:
    void insert(const KeyType& key, const ValueType& value);

    const boost::function<ValueType(const KeyType&)> func_;
    const size_t capacity_;

    /**
     * Stores a list of recently accessed values and references to their
     * associated keys.
     */
    typedef boost::bimaps::bimap<
        boost::bimaps::unordered_set_of<KeyType>,
        boost::bimaps::list_of<ValueType>
    > container_type;
    container_type container_;
};


template<typename KeyType, typename ValueType>
LruCache<KeyType, ValueType>::LruCache(
    const boost::function<ValueType(const KeyType&)>& func,
    const size_t size
) :
    func_(func),
    capacity_(size),
    container_()
{
    assert(size > 0);
}


template<typename KeyType, typename ValueType>
ValueType LruCache<KeyType, ValueType>::operator()(const KeyType& key)
{
    // Look for existing value
    const typename container_type::left_iterator iter =
        container_.left.find(key);
    if (container_.left.end() == iter)
    {
        // We don't have it, evaluate the function and insert its value
        const ValueType value = func_(key);
        insert(key, value);

        return value;
    }
    else
    {
        // Update access time
        container_.right.relocate(
            container_.right.end(),
            container_.project_right(iter)
        );
    }

    return iter->second;
}


template<typename KeyType, typename ValueType>
void LruCache<KeyType, ValueType>::insert(
    const KeyType& key,
    const ValueType& value
)
{
    assert(container_.size() <= capacity_);

    // Make sure we have enough space
    if (container_.size() == capacity_)
    {
        container_.right.erase(container_.right.begin());
    }

    container_.insert(
        typename container_type::value_type(key, value)
    );
}

#endif  // SRC_LRUCACHE_HPP_
