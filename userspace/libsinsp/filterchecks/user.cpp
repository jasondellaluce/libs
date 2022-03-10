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
#include "user.h"

///////////////////////////////////////////////////////////////////////////////
// sinsp_filter_check_user implementation
///////////////////////////////////////////////////////////////////////////////
const filtercheck_field_info sinsp_filter_check_user_fields[] =
{
	{PT_UINT32, EPF_NONE, PF_ID, "user.uid", "User ID", "user ID."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "user.name", "User Name", "user name."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "user.homedir", "Home Directory", "home directory of the user."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "user.shell", "Shell", "user's shell."},
	{PT_INT32, EPF_NONE, PF_ID, "user.loginuid", "Login User ID", "audit user id (auid)."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "user.loginname", "Login User Name", "audit user name (auid)."},
};

sinsp_filter_check_user::sinsp_filter_check_user()
{
	m_info.m_name = "user";
	m_info.m_desc = "Information about the user executing the specific event.";
	m_info.m_fields = sinsp_filter_check_user_fields;
	m_info.m_nfields = sizeof(sinsp_filter_check_user_fields) / sizeof(sinsp_filter_check_user_fields[0]);
	m_info.m_flags = filter_check_info::FL_WORKS_ON_THREAD_TABLE;
}

sinsp_filter_check* sinsp_filter_check_user::allocate_new()
{
	return (sinsp_filter_check*) new sinsp_filter_check_user();
}

uint8_t* sinsp_filter_check_user::extract(sinsp_evt *evt, OUT uint32_t* len, bool sanitize_strings)
{
	*len = 0;
	sinsp_threadinfo* tinfo = evt->get_thread_info();
	scap_userinfo* uinfo = nullptr;

	if(tinfo == NULL)
	{
		return NULL;
	}

	if(m_field_id != TYPE_UID && m_field_id != TYPE_LOGINUID && m_field_id != TYPE_LOGINNAME)
	{
		ASSERT(m_inspector != NULL);
		uinfo = m_inspector->get_user(tinfo->m_uid);
		ASSERT(uinfo != NULL);
		if(uinfo == NULL)
		{
			return NULL;
		}
	}

	switch(m_field_id)
	{
	case TYPE_UID:
		RETURN_EXTRACT_VAR(tinfo->m_uid);
	case TYPE_NAME:
		RETURN_EXTRACT_CSTR(uinfo->name);
	case TYPE_HOMEDIR:
		RETURN_EXTRACT_CSTR(uinfo->homedir);
	case TYPE_SHELL:
		RETURN_EXTRACT_CSTR(uinfo->shell);
	case TYPE_LOGINUID:
		RETURN_EXTRACT_VAR(tinfo->m_loginuid);
	case TYPE_LOGINNAME:
		ASSERT(m_inspector != NULL);
		uinfo = m_inspector->get_user(tinfo->m_loginuid);
		if(uinfo == NULL)
		{
			return NULL;
		}
		RETURN_EXTRACT_CSTR(uinfo->name);
	default:
		ASSERT(false);
		break;
	}

	return NULL;
}
