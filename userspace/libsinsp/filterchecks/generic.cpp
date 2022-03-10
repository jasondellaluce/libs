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

#include "common.h"
#include "generic.h"

///////////////////////////////////////////////////////////////////////////////
// sinsp_filter_check_event implementation
///////////////////////////////////////////////////////////////////////////////
const filtercheck_field_info sinsp_filter_check_gen_event_fields[] =
{
	{PT_UINT64, EPF_NONE, PF_ID, "evt.num", "Event Number", "event number."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "evt.time", "Time", "event timestamp as a time string that includes the nanosecond part."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "evt.time.s", "Time (s)", "event timestamp as a time string with no nanoseconds."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "evt.time.iso8601", "ISO 8601 Time", "event timestamp in ISO 8601 format, including nanoseconds and time zone offset (in UTC)."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "evt.datetime", "Datetime", "event timestamp as a time string that includes the date."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "evt.datetime.s", "Datetime (s)", "event timestamp as a datetime string with no nanoseconds."},
	{PT_ABSTIME, EPF_NONE, PF_DEC, "evt.rawtime", "Absolute Time", "absolute event timestamp, i.e. nanoseconds from epoch."},
	{PT_ABSTIME, EPF_NONE, PF_DEC, "evt.rawtime.s", "Absolute Time (s)", "integer part of the event timestamp (e.g. seconds since epoch)."},
	{PT_ABSTIME, EPF_NONE, PF_10_PADDED_DEC, "evt.rawtime.ns", "Absolute Time (ns)", "fractional part of the absolute event timestamp."},
	{PT_RELTIME, EPF_NONE, PF_10_PADDED_DEC, "evt.reltime", "Relative Time", "number of nanoseconds from the beginning of the capture."},
	{PT_RELTIME, EPF_NONE, PF_DEC, "evt.reltime.s", "Relative Time (s)", "number of seconds from the beginning of the capture."},
	{PT_RELTIME, EPF_NONE, PF_10_PADDED_DEC, "evt.reltime.ns", "Relative Time (ns)", "fractional part (in ns) of the time from the beginning of the capture."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "evt.pluginname", "Plugin Name", "if the event comes from a plugin, the name of the plugin that generated it. The plugin must be currently loaded."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "evt.plugininfo", "Plugin Info", "if the event comes from a plugin, a summary of the event as formatted by the plugin. The plugin must be currently loaded."},
};

sinsp_filter_check_gen_event::sinsp_filter_check_gen_event()
{
	m_info.m_name = "evt";
	m_info.m_shortdesc = "All event types";
	m_info.m_desc = "These fields can be used for all event types";
	m_info.m_fields = sinsp_filter_check_gen_event_fields;
	m_info.m_nfields = sizeof(sinsp_filter_check_gen_event_fields) / sizeof(sinsp_filter_check_gen_event_fields[0]);
	m_u64val = 0;
}

sinsp_filter_check_gen_event::~sinsp_filter_check_gen_event()
{
}

sinsp_filter_check* sinsp_filter_check_gen_event::allocate_new()
{
	return (sinsp_filter_check*) new sinsp_filter_check_gen_event();
}

Json::Value sinsp_filter_check_gen_event::extract_as_js(sinsp_evt *evt, OUT uint32_t* len)
{
	switch(m_field_id)
	{
	case TYPE_TIME:
	case TYPE_TIME_S:
	case TYPE_TIME_ISO8601:
	case TYPE_DATETIME:
	case TYPE_DATETIME_S:
		return (Json::Value::Int64)evt->get_ts();

	case TYPE_RAWTS:
	case TYPE_RAWTS_S:
	case TYPE_RAWTS_NS:
	case TYPE_RELTS:
	case TYPE_RELTS_S:
	case TYPE_RELTS_NS:
		return (Json::Value::Int64)*(uint64_t*)extract(evt, len);
	default:
		return Json::nullValue;
	}

	return Json::nullValue;
}

uint8_t* sinsp_filter_check_gen_event::extract(sinsp_evt *evt, OUT uint32_t* len, bool sanitize_strings)
{

	std::shared_ptr<sinsp_plugin> plugin;
	sinsp_source_plugin *splugin;
	sinsp_evt_param *parinfo;

	*len = 0;
	switch(m_field_id)
	{
	case TYPE_TIME:
		if(false)
		{
			m_strstorage = to_string(evt->get_ts());
		}
		else
		{
			sinsp_utils::ts_to_string(evt->get_ts(), &m_strstorage, false, true);
		}
		RETURN_EXTRACT_STRING(m_strstorage);
	case TYPE_TIME_S:
		sinsp_utils::ts_to_string(evt->get_ts(), &m_strstorage, false, false);
		RETURN_EXTRACT_STRING(m_strstorage);
	case TYPE_TIME_ISO8601:
		sinsp_utils::ts_to_iso_8601(evt->get_ts(), &m_strstorage);
		RETURN_EXTRACT_STRING(m_strstorage);
	case TYPE_DATETIME:
		sinsp_utils::ts_to_string(evt->get_ts(), &m_strstorage, true, true);
		RETURN_EXTRACT_STRING(m_strstorage);
	case TYPE_DATETIME_S:
		sinsp_utils::ts_to_string(evt->get_ts(), &m_strstorage, true, false);
		RETURN_EXTRACT_STRING(m_strstorage);
	case TYPE_RAWTS:
		m_u64val = evt->get_ts();
		RETURN_EXTRACT_VAR(m_u64val);
	case TYPE_RAWTS_S:
		m_u64val = evt->get_ts() / ONE_SECOND_IN_NS;
		RETURN_EXTRACT_VAR(m_u64val);
	case TYPE_RAWTS_NS:
		m_u64val = evt->get_ts() % ONE_SECOND_IN_NS;
		RETURN_EXTRACT_VAR(m_u64val);
	case TYPE_RELTS:
		m_u64val = evt->get_ts() - m_inspector->m_firstevent_ts;
		RETURN_EXTRACT_VAR(m_u64val);
	case TYPE_RELTS_S:
		m_u64val = (evt->get_ts() - m_inspector->m_firstevent_ts) / ONE_SECOND_IN_NS;
		RETURN_EXTRACT_VAR(m_u64val);
	case TYPE_RELTS_NS:
		m_u64val = (evt->get_ts() - m_inspector->m_firstevent_ts) % ONE_SECOND_IN_NS;
		RETURN_EXTRACT_VAR(m_u64val);
	case TYPE_NUMBER:
		m_u64val = evt->get_num();
		RETURN_EXTRACT_VAR(m_u64val);
	case TYPE_PLUGINNAME:
	case TYPE_PLUGININFO:
		plugin = m_inspector->get_plugin_by_evt(*evt);
		if (plugin == nullptr)
		{
			return NULL;
		}

		if(m_field_id == TYPE_PLUGINNAME)
		{
			m_strstorage = plugin->name();
		}
		else
		{
			parinfo = evt->get_param(1);
			splugin = static_cast<sinsp_source_plugin *>(plugin.get());
			m_strstorage = splugin->event_to_string((const uint8_t *) parinfo->m_val, parinfo->m_len);
		}

		RETURN_EXTRACT_STRING(m_strstorage);
	default:
		ASSERT(false);
		return NULL;
	}

	return NULL;
}
