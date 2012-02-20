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

#ifndef CACHE_MAP_HPP
#define CACHE_MAP_HPP

#include "DescribedException.hpp"
#include "warnUnusedResult.h"

#include <utility>
#include <map>

/**
 * Implementation of map that only allows a certain number of items to
 * be stored; if more items are added, the least recently accessed item
 * is removed.
 * @author Brandon Skari
 * @date January 25 2011
 */

template <typename KeyType, typename ValueType>
class CacheMap
{
public:
	explicit CacheMap(size_t maxItems);
	CacheMap(CacheMap<KeyType, ValueType>& rhs);
	
	~CacheMap();
	
	/**
	 * Gets the value of a particular key.
	 * @param key The key associated with the value.
	 * @return The value associated with the key.
	 */
	ValueType& operator[](const KeyType& key) WARN_UNUSED_RESULT;
	
	void swap(CacheMap& rhs);
	
	bool exists(const KeyType& key) WARN_UNUSED_RESULT;
	
	bool empty() const WARN_UNUSED_RESULT;
	size_t size() const WARN_UNUSED_RESULT;
	
private:
	const size_t maxItems_;
	std::map<KeyType, ValueType> items_;
	std::map<KeyType, ValueType> oldItems_;
	
	// Hidden methods
	CacheMap& operator=(const CacheMap& rhs);
};


template <typename KeyType, typename ValueType>
CacheMap<KeyType, ValueType>::CacheMap(const size_t max):
	maxItems_(max),
	items_(),
	oldItems_()
{
	if (max < 2)
	{
		throw DescribedException("CacheMap requires at least size 2");
	}
}


template <typename KeyType, typename ValueType>
CacheMap<KeyType, ValueType>::CacheMap(
	CacheMap<KeyType, ValueType> &rhs) :
		maxItems_(rhs.maxItems_),
		items_(rhs.newItems_),
		oldItems_()
{
}


template <typename KeyType, typename ValueType>
CacheMap<KeyType, ValueType>::~CacheMap()
{
}


template<typename KeyType, typename ValueType>
ValueType& CacheMap<KeyType, ValueType>::operator[](const KeyType& key)
{
	// If the key-value is already cached, then return it
	if (items_.end() != items_.find(key))
	{
		return items_[key];
	}
	
	// If we have space and it's cached in the old map, then copy it over
	if (items_.size() < maxItems_)
	{
		const typename std::map<KeyType, ValueType>::const_iterator i(
			oldItems_.find(key));
		items_[key] = i->second;
	}
	// We're out of space! Move the current cache to the old
	else
	{
		oldItems_.clear();
		items_.swap(oldItems_);
	}
	
	return items_[key];
}


template<typename KeyType, typename ValueType>
void CacheMap<KeyType, ValueType>::swap(CacheMap& rhs)
{
	swap(maxItems_, rhs.maxItems_);
	swap(items_, rhs.items_);
	swap(oldItems_, rhs.oldItems_);
}


namespace std
{
	template<typename KeyType, typename ValueType>
	void swap(CacheMap<KeyType, ValueType>& lhs, CacheMap<KeyType, ValueType>& rhs)
	{
		lhs.swap(rhs);
	}
}


template<typename KeyType, typename ValueType>
bool CacheMap<KeyType, ValueType>::exists(const KeyType& key)
{
	if (items_.end() != items_.find(key))
	{
		return true;
	}
	
	// If we have space and it's cached in the old items, then copy it over
	if (items_.size() < maxItems_)
	{
		const typename std::map<KeyType, ValueType>::const_iterator i(
			oldItems_.find(key));
		if (oldItems_.end() != i)
		{
			items_[key] = i->second;
			return true;
		}
	}
	
	return false;
}


template<typename KeyType, typename ValueType>
bool CacheMap<KeyType, ValueType>::empty() const
{
	return items_.empty();
}


template<typename KeyType, typename ValueType>
size_t CacheMap<KeyType, ValueType>::size() const
{
	return items_.size();
}

#endif
