/* Copyright (c) 2017, ARM Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef CONFIG_HH
#define CONFIG_HH

#include <map>
#include <string>

// Hold the configuration of the program.  Things
// like address and port to bind to, replicate servers,
// and other stuff all serialized into strings for now.
class Config
{
public:
	Config();
	~Config() {}

	std::string getValue(std::string key);
	void setValue(std::string key, std::string val);

private:
	std::map<std::string, std::string> config;
};

#endif
