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
// thread sinsp_filter_check_thread
//
class sinsp_filter_check_thread : public sinsp_filter_check
{
public:
	enum check_type
	{
		TYPE_PID = 0,
		TYPE_EXE = 1,
		TYPE_NAME = 2,
		TYPE_ARGS = 3,
		TYPE_ENV = 4,
		TYPE_CMDLINE = 5,
		TYPE_EXELINE = 6,
		TYPE_CWD = 7,
		TYPE_NTHREADS = 8,
		TYPE_NCHILDS = 9,
		TYPE_PPID = 10,
		TYPE_PNAME = 11,
		TYPE_PCMDLINE = 12,
		TYPE_APID = 13,
		TYPE_ANAME = 14,
		TYPE_LOGINSHELLID = 15,
		TYPE_DURATION = 16,
		TYPE_FDOPENCOUNT = 17,
		TYPE_FDLIMIT = 18,
		TYPE_FDUSAGE = 19,
		TYPE_VMSIZE = 20,
		TYPE_VMRSS = 21,
		TYPE_VMSWAP = 22,
		TYPE_PFMAJOR = 23,
		TYPE_PFMINOR = 24,
		TYPE_TID = 25,
		TYPE_ISMAINTHREAD = 26,
		TYPE_EXECTIME = 27,
		TYPE_TOTEXECTIME = 28,
		TYPE_CGROUPS = 29,
		TYPE_CGROUP = 30,
		TYPE_VTID = 31,
		TYPE_VPID = 32,
		TYPE_THREAD_CPU = 33,
		TYPE_THREAD_CPU_USER = 34,
		TYPE_THREAD_CPU_SYSTEM = 35,
		TYPE_THREAD_VMSIZE = 36,
		TYPE_THREAD_VMRSS = 37,
		TYPE_THREAD_VMSIZE_B = 38,
		TYPE_THREAD_VMRSS_B = 39,
		TYPE_SID = 40,
		TYPE_SNAME = 41,
		TYPE_TTY = 42,
		TYPE_EXEPATH = 43,
		TYPE_NAMETID = 44,
		TYPE_VPGID = 45,
		TYPE_IS_CONTAINER_HEALTHCHECK = 46,
		TYPE_IS_CONTAINER_LIVENESS_PROBE = 47,
		TYPE_IS_CONTAINER_READINESS_PROBE = 48,
		TYPE_IS_EXE_WRITABLE = 49,
	};

	sinsp_filter_check_thread();
	sinsp_filter_check* allocate_new();
	int32_t parse_field_name(const char* str, bool alloc_state, bool needed_for_filtering);
	uint8_t* extract(sinsp_evt *evt, OUT uint32_t* len, bool sanitize_strings = true);
	bool compare(sinsp_evt *evt);

private:
	uint64_t extract_exectime(sinsp_evt *evt);
	int32_t extract_arg(string fldname, string val, OUT const struct ppm_param_info** parinfo);
	uint8_t* extract_thread_cpu(sinsp_evt *evt, OUT uint32_t* len, sinsp_threadinfo* tinfo, bool extract_user, bool extract_system);
	inline bool compare_full_apid(sinsp_evt *evt);
	bool compare_full_aname(sinsp_evt *evt);

	int32_t m_argid;
	string m_argname;
	uint32_t m_tbool;
	string m_tstr;
	uint64_t m_u64val;
	int64_t m_s64val;
	double m_dval;
	vector<uint64_t> m_last_proc_switch_times;
	uint32_t m_th_state_id;
	uint64_t m_cursec_ts;
};
