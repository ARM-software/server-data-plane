/* Copyright (c) 2017, ARM Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef OBJPOOL_IMPL_HH
#define OBJPOOL_IMPL_HH

// The compiler will instantiate the number of static variables we need here
// based on the types of objPtrs we want to use this allocator for.
template <class T> std::vector<T*> ObjPool<T>::object_pool;
template <class T> std::list<T*> ObjPool<T>::free_list;

template <class T> std::mutex ObjPool<T>::free_list_lock;
template <class T> std::mutex ObjPool<T>::class_lock;
template <class T> uint32_t ObjPool<T>::ref_cnt = 0;
template <class T> int ObjPool<T>::pool_id = -1;
template <class T> uint32_t ObjPool<T>::low_wm = 0;
template <class T> odp_atomic_u32_t ObjPool<T>::low_wm_hit;
template <class T> uint32_t ObjPool<T>::hi_wm = 0;

// Handle design: 10b pool_id | 24b object id | 30b reserved/user defined
template <class T>
ObjPool<T>::ObjPool(int numObjs)
{
	// We are a pseudo-singleton class, meaning we only allocate our
	// static stuff one time, so we need to guard against multiple
	// ObjPool object creations.  If this is not the first invocation,
	// then numObjs is ignored.
	// Take the class lock whenever we manipulate the static members of
	// the class other than the free_list.
	ObjPool<T>::class_lock.lock();

	if (ObjPool<T>::ref_cnt == 0) {
		ObjPool<T>::ref_cnt++;
		// Our handle object can only represent 8M objects
		if (numObjs > ((1ULL << 24) - 1)) numObjs = ((1ULL << 24) - 1);
		// If we are the first, then lets register and populate the
		// global pool of objects
		ObjPool<T>::pool_id = this->registerPool();
		uint64_t lcl_id = ObjPool<T>::pool_id;

		ObjPool<T>::object_pool.resize(numObjs);
		uint64_t obj_id = 0;
		// Take the free_list lock whenever we manipulate the list
		ObjPool<T>::free_list_lock.lock();
		for (auto itr = ObjPool<T>::object_pool.begin();
		     itr != ObjPool<T>::object_pool.end(); itr++){
			uint64_t handle = (lcl_id << 54) | (obj_id << 30) | 0x0;

			*itr = new T(handle);

			// Add to the free_list
			ObjPool<T>::free_list.push_back(*itr);
			obj_id++;
		}
		ObjPool<T>::free_list_lock.unlock();

		ObjPool<T>::low_wm = numObjs / 4;
		ObjPool<T>::hi_wm = numObjs / 2;
		odp_atomic_init_u32(&ObjPool<T>::low_wm_hit, 0);
	} else {
		// If we already allocated, just increase ref_cnt
		ObjPool<T>::ref_cnt++;
	}

	ObjPool<T>::class_lock.unlock();
}

template <class T>
ObjPool<T>::~ObjPool()
{
	ObjPool<T>::class_lock.lock();

	ObjPool<T>::ref_cnt--;

	// If we are the last instance, deallocate everything
	if (ObjPool<T>::ref_cnt == 0) {
		ObjPool<T>::free_list_lock.lock();
		for (auto itr = ObjPool<T>::object_pool.begin();
		     itr != ObjPool<T>::object_pool.end();
		     itr++) {
			delete *itr;
		}
		while (!ObjPool<T>::free_list.empty()) {
			ObjPool<T>::free_list.pop_front();
		}
		ObjPool<T>::free_list_lock.unlock();
	}

	this->unregisterPool(ObjPool<T>::pool_id);

	ObjPool<T>::class_lock.unlock();
}

template <class T>
T* ObjPool<T>::allocateObj()
{
	T* obj = nullptr;
	if (local_freelist.size()) {
		obj = local_freelist.front();
		// make sure the object is actually free
		assert(obj->getState() == 0);

		local_freelist.pop_front();
	} else {
		// If local free_list cache does not have any lines,
		// then grab it from the global pool.  Need to take a lock
		// (or in the future, do a lockless algo).
		ObjPool<T>::free_list_lock.lock();

		if (ObjPool<T>::free_list.size()) {
			obj = ObjPool<T>::free_list.front();
			assert(obj->getState() == 0);
			ObjPool<T>::free_list.pop_front();
		}

		ObjPool<T>::free_list_lock.unlock();

		// Set low_wm outside critical section to hopefully reduce
		// lock contention.
		uint32_t wm_hit = odp_atomic_load_u32(&ObjPool<T>::low_wm_hit);
		if (ObjPool<T>::free_list.size() < ObjPool<T>::low_wm &&
		    !wm_hit) {
			odp_atomic_cas_u32(&ObjPool<T>::low_wm_hit, &wm_hit, 1);
		}
	}


	return obj;
}

template <class T>
T* ObjPool<T>::findItem(uint64_t objHandle)
{
	uint64_t mask = 0x003fffffc0000000;
	uint64_t idx = (objHandle & mask) >> 30;
	return ObjPool<T>::object_pool[idx];
}

template <class T>
object* ObjPool<T>::findObject(uint64_t objHandle)
{
	uint64_t mask = 0x003fffffc0000000;
	uint64_t idx = (objHandle & mask) >> 30;
	return dynamic_cast<object*>(ObjPool<T>::object_pool[idx]);
}

template <class T>
void ObjPool<T>::freeObj(T *obj)
{
	// Reset all the internal tracking data to a clean
	// state.
	assert(obj->getState());
	obj->cleanObject();

	// Put it into the local freelist
	local_freelist.push_back(obj);

	uint32_t wm_hit = odp_atomic_load_u32(&ObjPool<T>::low_wm_hit);

	if (wm_hit) {
		std::list<T*> objs;
		int i = local_freelist.size() / 2;

		while (i && local_freelist.size()) {
			objs.push_back(local_freelist.front());
			local_freelist.pop_front();
			i--;
		}

		ObjPool<T>::free_list_lock.lock();

		ObjPool<T>::free_list.splice(ObjPool<T>::free_list.begin(),
					     objs);
		ObjPool<T>::free_list_lock.unlock();

		// Try to unset the low_wm_hit if the global freelist has enough
		// objects.
		uint32_t wm_hit = odp_atomic_load_u32(&ObjPool<T>::low_wm_hit);
		if (ObjPool<T>::free_list.size() > ObjPool<T>::hi_wm && wm_hit) {
			odp_atomic_cas_u32(&ObjPool<T>::low_wm_hit, &wm_hit, 1);
		}
	}
}

#endif
