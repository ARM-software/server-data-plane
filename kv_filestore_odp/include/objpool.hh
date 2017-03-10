/* Copyright (c) 2017, ARM Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef OBJPOOL_HH
#define OBJPOOL_HH

#include <odp.h>

#include <list>
#include <mutex>
#include <vector>

#include "include/object.hh"

// Will track some additional state
int initializeObjPools();

// Base class for ObjPools so we can resolve
// templated classes at runtime using dynamic_cast 
// and identify what they are in a crude attempt at reflection.
// This is also a pseudo-singleton class as it manages some
// global variables for us.
class ObjPoolBase {
public:
	ObjPoolBase();
	virtual ~ObjPoolBase();

	static object* lookupObject(uint64_t objHandle);
	virtual object* findObject(uint64_t objHandle) = 0;

protected:
	int registerPool();
	void unregisterPool(int id);

private:
	static std::vector<ObjPoolBase *> objPools;
	static std::mutex class_lock;
	static uint32_t num_pools;
};

// Pseudo-Singleton class for keeping around a global pool of
// objects for easy recovery on response packets.
template <class T>
class ObjPool : public ObjPoolBase {
public:
	ObjPool(int numObjs);
	~ObjPool();

	T* allocateObj();
	T* findItem(uint64_t objHandle);
	object* findObject(uint64_t objHandle);
	void freeObj(T *obj);

private:
	// 2D array of for multiple pools
	static std::vector<T*> object_pool;
	static std::list<T*> free_list;
	static std::mutex free_list_lock;
	static std::mutex class_lock;
	static odp_atomic_u32_t low_wm_hit; // Set when 1/4 of all allocated objects remain
	static uint32_t low_wm;
	static uint32_t hi_wm; // This is the value when the free_list reaches
			       // this we clear low_wm_hit.  About 1/2 of all allocated objects.
	static uint32_t ref_cnt;
	static int pool_id;

	std::list<T*> local_freelist;
};

#include "include/objpool_impl.hh"

#endif
