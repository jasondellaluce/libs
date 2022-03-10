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
// Fake filter check used by the event formatter to render format text
//
class rawstring_check : public sinsp_filter_check
{
public:
	rawstring_check(string text);
	sinsp_filter_check* allocate_new();
	void set_text(string text);
	int32_t parse_field_name(const char* str, bool alloc_state, bool needed_for_filtering);
	uint8_t* extract(sinsp_evt *evt, OUT uint32_t* len, bool sanitize_strings = true);

	// XXX this is overkill and wasted for most of the fields.
	// It could be optimized by dynamically allocating the right amount
	// of memory, but we don't care for the moment since we expect filters
	// to be pretty small.
	string m_text;
	uint32_t m_text_len;
};

//
// For internal use
//
class sinsp_filter_check_reference : public sinsp_filter_check
{
public:
	enum alignment
	{
		ALIGN_LEFT,
		ALIGN_RIGHT,
	};

	sinsp_filter_check_reference();
	sinsp_filter_check* allocate_new();
	inline void set_val(ppm_param_type type, uint8_t* val,
		int32_t len, uint32_t cnt,
		ppm_print_format print_format)
	{
		m_finfo.m_type = type;
		m_val = val;
		m_len = len;
		m_cnt = cnt;
		m_print_format = print_format;
	}
	int32_t parse_field_name(const char* str, bool alloc_state, bool needed_for_filtering);
	uint8_t* extract(sinsp_evt *evt, OUT uint32_t* len, bool sanitize_strings = true);
	char* tostring_nice(sinsp_evt* evt, uint32_t str_len, uint64_t time_delta);
	Json::Value tojson(sinsp_evt* evt, uint32_t str_len, uint64_t time_delta);

private:
	inline char* format_bytes(double val, uint32_t str_len, bool is_int);
	inline char* format_time(uint64_t val, uint32_t str_len);
	char* print_double(uint8_t* rawval, uint32_t str_len);
	char* print_int(uint8_t* rawval, uint32_t str_len);

	filtercheck_field_info m_finfo;
	uint8_t* m_val;
	uint32_t m_len;
	double m_cnt;		// For averages, this stores the entry count
	ppm_print_format m_print_format;
};

//
// For internal use
//
class sinsp_filter_check_utils : public sinsp_filter_check
{
public:
	enum check_type
	{
		TYPE_CNT,
	};

	sinsp_filter_check_utils();
	sinsp_filter_check* allocate_new();
	uint8_t* extract(sinsp_evt *evt, OUT uint32_t* len, bool sanitize_strings = true);

private:
	uint64_t m_cnt;
};
