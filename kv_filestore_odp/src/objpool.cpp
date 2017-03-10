/* Copyright (c) 2017, ARM Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include "include/objpool.hh"

#include <typeinfo>

std::vector<ObjPoolBase*> ObjPoolBase::objPools;
std::mutex ObjPoolBase::class_lock;
uint32_t ObjPoolBase::num_pools = 0;

ObjPoolBase::ObjPoolBase()
{}

ObjPoolBase::~ObjPoolBase()
{
}

object* ObjPoolBase::lookupObject(uint64_t objHandle)
{
	uint64_t mask = 0xffd0000000000000ULL;
	uint64_t idx = (objHandle & mask) >> 54;
	ObjPoolBase *objPool = ObjPoolBase::objPools[idx];

	// call the derived class and get the object
	return objPool->findObject(objHandle);
}

int ObjPoolBase::registerPool()
{
	int pool_id = -1;
	// May be constructing multiple objpools
	ObjPoolBase::class_lock.lock();

	// Lets find a pool id to use, reuse one that is null first

	if (ObjPoolBase::objPools.size() < ObjPoolBase::num_pools + 1) {
		ObjPoolBase::objPools.push_back(this);
		pool_id = ObjPoolBase::objPools.size() - 1;
	} else {
		// Otherwise, find the first nullptr and set it to our pool
		for (unsigned int i = 0; i < ObjPoolBase::objPools.size(); i++) {
			if (ObjPoolBase::objPools[i] == nullptr) {
				pool_id = i;
				ObjPoolBase::objPools[i] = this;
			}
		}
	}

	ObjPoolBase::class_lock.unlock();

	return pool_id;
}

void ObjPoolBase::unregisterPool(int id)
{
	ObjPoolBase::class_lock.lock();

	ObjPoolBase::objPools[id] = nullptr;

	ObjPoolBase::class_lock.unlock();
}
// Handle design: 10b pool_id | 24b object id | 30b reserved/user defined


