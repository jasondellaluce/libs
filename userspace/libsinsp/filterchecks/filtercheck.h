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

#include <unordered_set>
#include <json/json.h>
#include "../sinsp.h"
#include "../filter_value.h"
#include "../prefix_search.h"

bool flt_compare(cmpop op, ppm_param_type type, void* operand1, void* operand2, uint32_t op1_len = 0, uint32_t op2_len = 0);
bool flt_compare_avg(cmpop op, ppm_param_type type, void* operand1, void* operand2, uint32_t op1_len, uint32_t op2_len, uint32_t cnt1, uint32_t cnt2);
bool flt_compare_ipv4net(cmpop op, uint64_t operand1, const ipv4net* operand2);
bool flt_compare_ipv6net(cmpop op, const ipv6addr *operand1, const ipv6net *operand2);

class operand_info
{
public:
	uint32_t m_id;
	ppm_param_type m_type;
	string m_name;
	string m_description;
};

class check_extraction_cache_entry
{
public:
	uint64_t m_evtnum = UINT64_MAX;
	uint8_t* m_res;
};

class check_eval_cache_entry
{
public:
	uint64_t m_evtnum = UINT64_MAX;
	bool m_res;
};

///////////////////////////////////////////////////////////////////////////////
// The filter check interface
// NOTE: in order to add a new type of filter check, you need to add a class for
//       it and then add it to new_filter_check_from_name.
///////////////////////////////////////////////////////////////////////////////

class sinsp_filter_check : public gen_event_filter_check
{
public:
	sinsp_filter_check();

	virtual ~sinsp_filter_check()
	{
	}

	//
	// Allocate a new check of the same type.
	// Every filtercheck plugin must implement this.
	//
	virtual sinsp_filter_check* allocate_new() = 0;

	//
	// Get the list of fields that this check exports
	//
	virtual filter_check_info* get_fields()
	{
		return &m_info;
	}

	//
	// Parse the name of the field.
	// Returns the length of the parsed field if successful, an exception in
	// case of error.
	//
	virtual int32_t parse_field_name(const char* str, bool alloc_state, bool needed_for_filtering);

	//
	// If this check is used by a filter, extract the constant to compare it to
	// Doesn't return the field length because the filtering engine can calculate it.
	//
	void add_filter_value(const char* str, uint32_t len, uint32_t i = 0 );
	virtual size_t parse_filter_value(const char* str, uint32_t len, uint8_t *storage, uint32_t storage_len);

	//
	// Called after parsing for optional validation of the filter value
	//
	void validate_filter_value(const char* str, uint32_t len) {}

	//
	// Return the info about the field that this instance contains
	//
	virtual const filtercheck_field_info* get_field_info();

	//
	// Extract the field from the event. In sanitize_strings is true, any
	// string values are sanitized to remove nonprintable characters.
	//
	uint8_t* extract(gen_event *evt, OUT uint32_t* len, bool sanitize_strings = true);
	virtual uint8_t* extract(sinsp_evt *evt, OUT uint32_t* len, bool sanitize_strings = true) = 0;

	//
	// Wrapper for extract() that implements caching to speed up multiple extractions of the same value,
	// which are common in Falco.
	//
	uint8_t* extract_cached(sinsp_evt *evt, OUT uint32_t* len, bool sanitize_strings = true);

	//
	// Extract the field as json from the event (by default, fall
	// back to the regular extract functionality)
	//
	virtual Json::Value extract_as_js(sinsp_evt *evt, OUT uint32_t* len)
	{
		return Json::nullValue;
	}

	virtual const std::set<uint16_t> &evttypes() override;
	const std::set<uint16_t> &possible_evttypes() override;

	//
	// Compare the field with the constant value obtained from parse_filter_value()
	//
	bool compare(gen_event *evt);
	virtual bool compare(sinsp_evt *evt);

	//
	// Extract the value from the event and convert it into a string
	//
	virtual char* tostring(sinsp_evt* evt);

	//
	// Extract the value from the event and convert it into a Json value
	// or object
	//
	virtual Json::Value tojson(sinsp_evt* evt);

	sinsp* m_inspector;
	bool m_needs_state_tracking = false;
	sinsp_field_aggregation m_aggregation;
	sinsp_field_aggregation m_merge_aggregation;
	check_eval_cache_entry* m_eval_cache_entry = NULL;
	check_extraction_cache_entry* m_extraction_cache_entry = NULL;

protected:
	bool flt_compare(cmpop op, ppm_param_type type, void* operand1, uint32_t op1_len = 0, uint32_t op2_len = 0);

	char* rawval_to_string(uint8_t* rawval,
			       ppm_param_type ptype,
			       ppm_print_format print_format,
			       uint32_t len);
	Json::Value rawval_to_json(uint8_t* rawval, ppm_param_type ptype, ppm_print_format print_format, uint32_t len);
	void string_to_rawval(const char* str, uint32_t len, ppm_param_type ptype);

	char m_getpropertystr_storage[1024];
	std::vector<std::vector<uint8_t>> m_val_storages;
	inline uint8_t* filter_value_p(uint16_t i = 0) { return &m_val_storages[i][0]; }
	inline std::vector<uint8_t>* filter_value(uint16_t i = 0) { return &m_val_storages[i]; }

	std::unordered_set<filter_value_t,
		g_hash_membuf,
		g_equal_to_membuf> m_val_storages_members;

	path_prefix_search m_val_storages_paths;

	uint32_t m_val_storages_min_size;
	uint32_t m_val_storages_max_size;

	const filtercheck_field_info* m_field;
	filter_check_info m_info;
	uint32_t m_field_id;
	uint32_t m_th_state_id;
	uint32_t m_val_storage_len;

private:
	void set_inspector(sinsp* inspector);

	std::set<uint16_t> s_all_event_types;

friend class filter_check_list;
friend class sinsp_filter_optimizer;
friend class chk_compare_helper;
};
