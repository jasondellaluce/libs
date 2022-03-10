/*
Copyright (C) 2022 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/

#pragma once

#include "filtercheck.h"

//
// filterchecks that will work on any generic event
//
class sinsp_filter_check_gen_event : public sinsp_filter_check
{
public:
	enum check_type
	{
		TYPE_NUMBER = 0,
		TYPE_TIME = 1,
		TYPE_TIME_S = 2,
		TYPE_TIME_ISO8601 = 3,
		TYPE_DATETIME = 4,
		TYPE_DATETIME_S = 5,
		TYPE_RAWTS = 6,
		TYPE_RAWTS_S = 7,
		TYPE_RAWTS_NS = 8,
		TYPE_RELTS = 9,
		TYPE_RELTS_S = 10,
		TYPE_RELTS_NS = 11,
		TYPE_PLUGINNAME = 12,
		TYPE_PLUGININFO = 13,
	};

	sinsp_filter_check_gen_event();
	~sinsp_filter_check_gen_event();
	sinsp_filter_check* allocate_new();
	uint8_t* extract(sinsp_evt *evt, OUT uint32_t* len, bool sanitize_strings = true);
	Json::Value extract_as_js(sinsp_evt *evt, OUT uint32_t* len);

	uint64_t m_u64val;
	string m_strstorage;
};
