/* Copyright (c) 2017, ARM Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <string>

#ifndef EXCEPTION_HH
#define EXCEPTION_HH

class QdofsException : public std::exception
{
public:
	QdofsException(std::string _msg)
	{
		msg = _msg;
	}

	QdofsException()
	{
		msg = "unknown cause";
	}

	virtual const char* what() const throw()
	{
		std::string str = "Qdofs exception: " + msg + "\n";
		return str.c_str();
	}

protected:
	std::string msg;
};

#endif
