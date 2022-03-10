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
#include "group.h"

///////////////////////////////////////////////////////////////////////////////
// sinsp_filter_check_group implementation
///////////////////////////////////////////////////////////////////////////////
const filtercheck_field_info sinsp_filter_check_group_fields[] =
{
	{PT_UINT64, EPF_NONE, PF_ID, "group.gid", "Group ID", "group ID."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "group.name", "Group Name", "group name."},
};

sinsp_filter_check_group::sinsp_filter_check_group()
{
	m_info.m_name = "group";
	m_info.m_desc = "Information about the user group.";
	m_info.m_fields = sinsp_filter_check_group_fields;
	m_info.m_nfields = sizeof(sinsp_filter_check_group_fields) / sizeof(sinsp_filter_check_group_fields[0]);
	m_info.m_flags = filter_check_info::FL_WORKS_ON_THREAD_TABLE;
}

sinsp_filter_check* sinsp_filter_check_group::allocate_new()
{
	return (sinsp_filter_check*) new sinsp_filter_check_group();
}

uint8_t* sinsp_filter_check_group::extract(sinsp_evt *evt, OUT uint32_t* len, bool sanitize_strings)
{
	*len = 0;
	sinsp_threadinfo* tinfo = evt->get_thread_info();

	if(tinfo == NULL)
	{
		return NULL;
	}

	switch(m_field_id)
	{
	case TYPE_GID:
		RETURN_EXTRACT_VAR(tinfo->m_gid);
	case TYPE_NAME:
		{
			unordered_map<uint32_t, scap_groupinfo*>::iterator it;

			ASSERT(m_inspector != NULL);
			auto ginfo = m_inspector->get_group(tinfo->m_gid);
			if (ginfo == NULL)
			{
				return NULL;
			}
			RETURN_EXTRACT_CSTR(ginfo->name);
		}
	default:
		ASSERT(false);
		break;
	}

	return NULL;
}
