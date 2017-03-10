/* Copyright (c) 2017, ARM Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef OBJECT_HH
#define OBJECT_HH

// Opaque base class to use to work with object pools.
// Not sure how well this really works, but allows us
// to make different transaction classes in the future.
class object {
public:
	virtual ~object() {}
	virtual void cleanObject() = 0;
	// A simple state check, 0 means free, 1 means alloc'ed
	virtual int getState() = 0;
};

#endif
