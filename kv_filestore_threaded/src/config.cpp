/* Copyright (c) 2017, ARM Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include "include/config.hh"

Config::Config()
{
	config.clear();
}

// Accessor functions for our configuration structure
std::string Config::getValue(std::string key)
{
	auto itr = config.find(key);
	if (itr == config.end()) {
		return std::string("");
	} else {
		return itr->second;
	}
}

void Config::setValue(std::string key, std::string val)
{
	auto itr = config.find(key);

	if (itr == config.end()) {
		config[key] = val;
	} else {
		itr->second = val;
	}
}
