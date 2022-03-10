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
#include "thread.h"

///////////////////////////////////////////////////////////////////////////////
// sinsp_filter_check_thread implementation
///////////////////////////////////////////////////////////////////////////////
const filtercheck_field_info sinsp_filter_check_thread_fields[] =
{
	{PT_INT64, EPF_NONE, PF_ID, "proc.pid", "Process ID", "the id of the process generating the event."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "proc.exe", "First Argument", "the first command line argument (usually the executable name or a custom one)."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "proc.name", "Name", "the name (excluding the path) of the executable generating the event."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "proc.args", "Arguments", "the arguments passed on the command line when starting the process generating the event."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "proc.env", "Environment", "the environment variables of the process generating the event."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "proc.cmdline", "Command Line", "full process command line, i.e. proc.name + proc.args."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "proc.exeline", "Executable Command Line", "full process command line, with exe as first argument, i.e. proc.exe + proc.args."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "proc.cwd", "Current Working Directory", "the current working directory of the event."},
	{PT_UINT32, EPF_NONE, PF_DEC, "proc.nthreads", "Threads", "the number of threads that the process generating the event currently has, including the main process thread."},
	{PT_UINT32, EPF_NONE, PF_DEC, "proc.nchilds", "Children", "the number of child threads that the process generating the event currently has. This excludes the main process thread."},
	{PT_INT64, EPF_NONE, PF_ID, "proc.ppid", "Parent Process ID", "the pid of the parent of the process generating the event."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "proc.pname", "Parent Name", "the name (excluding the path) of the parent of the process generating the event."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "proc.pcmdline", "Parent Command Line", "the full command line (proc.name + proc.args) of the parent of the process generating the event."},
	{PT_INT64, EPF_NONE, PF_ID, "proc.apid", "Ancestor Process ID", "the pid of one of the process ancestors. E.g. proc.apid[1] returns the parent pid, proc.apid[2] returns the grandparent pid, and so on. proc.apid[0] is the pid of the current process. proc.apid without arguments can be used in filters only and matches any of the process ancestors, e.g. proc.apid=1234."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "proc.aname", "Ancestor Name", "the name (excluding the path) of one of the process ancestors. E.g. proc.aname[1] returns the parent name, proc.aname[2] returns the grandparent name, and so on. proc.aname[0] is the name of the current process. proc.aname without arguments can be used in filters only and matches any of the process ancestors, e.g. proc.aname=bash."},
	{PT_INT64, EPF_NONE, PF_ID, "proc.loginshellid", "Login Shell ID", "the pid of the oldest shell among the ancestors of the current process, if there is one. This field can be used to separate different user sessions, and is useful in conjunction with chisels like spy_user."},
	{PT_RELTIME, EPF_NONE, PF_DEC, "proc.duration", "Duration", "number of nanoseconds since the process started."},
	{PT_UINT64, EPF_NONE, PF_DEC, "proc.fdopencount", "FD Count", "number of open FDs for the process"},
	{PT_INT64, EPF_NONE, PF_DEC, "proc.fdlimit", "FD Limit", "maximum number of FDs the process can open."},
	{PT_DOUBLE, EPF_NONE, PF_DEC, "proc.fdusage", "FD Usage", "the ratio between open FDs and maximum available FDs for the process."},
	{PT_UINT64, EPF_NONE, PF_DEC, "proc.vmsize", "VM Size", "total virtual memory for the process (as kb)."},
	{PT_UINT64, EPF_NONE, PF_DEC, "proc.vmrss", "VM RSS", "resident non-swapped memory for the process (as kb)."},
	{PT_UINT64, EPF_NONE, PF_DEC, "proc.vmswap", "VM Swap", "swapped memory for the process (as kb)."},
	{PT_UINT64, EPF_NONE, PF_DEC, "thread.pfmajor", "Major Page Faults", "number of major page faults since thread start."},
	{PT_UINT64, EPF_NONE, PF_DEC, "thread.pfminor", "Minor Page Faults", "number of minor page faults since thread start."},
	{PT_INT64, EPF_NONE, PF_ID, "thread.tid", "Thread ID", "the id of the thread generating the event."},
	{PT_BOOL, EPF_NONE, PF_NA, "thread.ismain", "Main Thread", "'true' if the thread generating the event is the main one in the process."},
	{PT_RELTIME, EPF_NONE, PF_DEC, "thread.exectime", "Scheduled Thread CPU Time", "CPU time spent by the last scheduled thread, in nanoseconds. Exported by switch events only."},
	{PT_RELTIME, EPF_NONE, PF_DEC, "thread.totexectime", "Current Thread CPU Time", "Total CPU time, in nanoseconds since the beginning of the capture, for the current thread. Exported by switch events only."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "thread.cgroups", "Thread Cgroups", "all the cgroups the thread belongs to, aggregated into a single string."},
	{PT_CHARBUF, EPF_REQUIRES_ARGUMENT, PF_NA, "thread.cgroup", "Thread Cgroup", "the cgroup the thread belongs to, for a specific subsystem. E.g. thread.cgroup.cpuacct."},
	{PT_INT64, EPF_NONE, PF_ID, "thread.vtid", "Virtual Thread ID", "the id of the thread generating the event as seen from its current PID namespace."},
	{PT_INT64, EPF_NONE, PF_ID, "proc.vpid", "Virtual Process ID", "the id of the process generating the event as seen from its current PID namespace."},
	{PT_DOUBLE, EPF_NONE, PF_NA, "thread.cpu", "Thread CPU", "the CPU consumed by the thread in the last second."},
	{PT_DOUBLE, EPF_NONE, PF_NA, "thread.cpu.user", "Thread User CPU", "the user CPU consumed by the thread in the last second."},
	{PT_DOUBLE, EPF_NONE, PF_NA, "thread.cpu.system", "Thread System CPU", "the system CPU consumed by the thread in the last second."},
	{PT_UINT64, EPF_NONE, PF_DEC, "thread.vmsize", "Thread VM Size (kb)", "For the process main thread, this is the total virtual memory for the process (as kb). For the other threads, this field is zero."},
	{PT_UINT64, EPF_NONE, PF_DEC, "thread.vmrss", "Thread VM RSS (kb)", "For the process main thread, this is the resident non-swapped memory for the process (as kb). For the other threads, this field is zero."},
	{PT_UINT64, EPF_TABLE_ONLY, PF_DEC, "thread.vmsize.b", "Thread VM Size (b)", "For the process main thread, this is the total virtual memory for the process (in bytes). For the other threads, this field is zero."},
	{PT_UINT64, EPF_TABLE_ONLY, PF_DEC, "thread.vmrss.b", "Thread VM RSS (b)", "For the process main thread, this is the resident non-swapped memory for the process (in bytes). For the other threads, this field is zero."},
	{PT_INT64, EPF_NONE, PF_ID, "proc.sid", "Process Session ID", "the session id of the process generating the event."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "proc.sname", "Process Session Name", "the name of the current process's session leader. This is either the process with pid=proc.sid or the eldest ancestor that has the same sid as the current process."},
	{PT_INT32, EPF_NONE, PF_ID, "proc.tty", "Process TTY", "The controlling terminal of the process. 0 for processes without a terminal."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "proc.exepath", "Process Executable Path", "The full executable path of the process."},
	{PT_CHARBUF, EPF_TABLE_ONLY, PF_NA, "thread.nametid", "Thread Name + ID", "this field chains the process name and tid of a thread and can be used as a specific identifier of a thread for a specific execve."},
	{PT_INT64, EPF_NONE, PF_ID, "proc.vpgid", "Process Virtual Group ID", "the process group id of the process generating the event, as seen from its current PID namespace."},
	{PT_BOOL, EPF_NONE, PF_NA, "proc.is_container_healthcheck", "Process Is Container Healthcheck", "true if this process is running as a part of the container's health check."},
	{PT_BOOL, EPF_NONE, PF_NA, "proc.is_container_liveness_probe", "Process Is Container Liveness", "true if this process is running as a part of the container's liveness probe."},
	{PT_BOOL, EPF_NONE, PF_NA, "proc.is_container_readiness_probe", "Process Is Container Readiness", "true if this process is running as a part of the container's readiness probe."},
	{PT_BOOL, EPF_NONE, PF_NA, "proc.is_exe_writable", "Process Executable Is Writable", "true if this process' executable file is writable by the same user that spawned the process."},
};

sinsp_filter_check_thread::sinsp_filter_check_thread()
{
	m_info.m_name = "process";
	m_info.m_desc = "Additional information about the process and thread executing the syscall event.";
	m_info.m_fields = sinsp_filter_check_thread_fields;
	m_info.m_nfields = sizeof(sinsp_filter_check_thread_fields) / sizeof(sinsp_filter_check_thread_fields[0]);
	m_info.m_flags = filter_check_info::FL_WORKS_ON_THREAD_TABLE;

	m_u64val = 0;
	m_cursec_ts = 0;
}

sinsp_filter_check* sinsp_filter_check_thread::allocate_new()
{
	return (sinsp_filter_check*) new sinsp_filter_check_thread();
}

int32_t sinsp_filter_check_thread::extract_arg(string fldname, string val, OUT const struct ppm_param_info** parinfo)
{
	uint32_t parsed_len = 0;

	//
	// 'arg' and 'resarg' are handled in a custom way
	//
	if(m_field_id == TYPE_APID || m_field_id == TYPE_ANAME)
	{
		if(val[fldname.size()] == '[')
		{
			parsed_len = (uint32_t)val.find(']');
			string numstr = val.substr(fldname.size() + 1, parsed_len - fldname.size() - 1);
			m_argid = sinsp_numparser::parsed32(numstr);
			parsed_len++;
		}
		else
		{
			throw sinsp_exception("filter syntax error: " + val);
		}
	}
	else if(m_field_id == TYPE_CGROUP)
	{
		if(val[fldname.size()] == '.')
		{
			size_t endpos;
			for(endpos = fldname.size() + 1; endpos < val.length(); ++endpos)
			{
				if(!isalpha(val[endpos])
					&& val[endpos] != '_')
				{
					break;
				}
			}

			parsed_len = (uint32_t)endpos;
			m_argname = val.substr(fldname.size() + 1, endpos - fldname.size() - 1);
		}
		else
		{
			throw sinsp_exception("filter syntax error: " + val);
		}
	}

	return parsed_len;
}

int32_t sinsp_filter_check_thread::parse_field_name(const char* str, bool alloc_state, bool needed_for_filtering)
{
	string val(str);

	if(string(val, 0, sizeof("arg") - 1) == "arg")
	{
		//
		// 'arg' is handled in a custom way
		//
		throw sinsp_exception("filter error: proc.arg filter not implemented yet");
	}
	else if(string(val, 0, sizeof("proc.apid") - 1) == "proc.apid")
	{
		m_field_id = TYPE_APID;
		m_field = &m_info.m_fields[m_field_id];

		int32_t res = 0;

		try
		{
			res = extract_arg("proc.apid", val, NULL);
		}
		catch(...)
		{
			if(val == "proc.apid")
			{
				m_argid = -1;
				res = (int32_t)val.size();
			}
		}

		return res;
	}
	else if(string(val, 0, sizeof("proc.aname") - 1) == "proc.aname")
	{
		m_field_id = TYPE_ANAME;
		m_field = &m_info.m_fields[m_field_id];

		int32_t res = 0;

		try
		{
			res = extract_arg("proc.aname", val, NULL);
		}
		catch(...)
		{
			if(val == "proc.aname")
			{
				m_argid = -1;
				res = (int32_t)val.size();
			}
		}

		return res;
	}
	else if(string(val, 0, sizeof("thread.totexectime") - 1) == "thread.totexectime")
	{
		//
		// Allocate thread storage for the value
		//
		if(alloc_state)
		{
			m_th_state_id = m_inspector->reserve_thread_memory(sizeof(uint64_t));
		}

		return sinsp_filter_check::parse_field_name(str, alloc_state, needed_for_filtering);
	}
	else if(string(val, 0, sizeof("thread.cgroup") - 1) == "thread.cgroup" &&
			string(val, 0, sizeof("thread.cgroups") - 1) != "thread.cgroups")
	{
		m_field_id = TYPE_CGROUP;
		m_field = &m_info.m_fields[m_field_id];

		return extract_arg("thread.cgroup", val, NULL);
	}
	else if(string(val, 0, sizeof("thread.cpu") - 1) == "thread.cpu")
	{
		if(alloc_state)
		{
			m_th_state_id = m_inspector->reserve_thread_memory(sizeof(uint64_t));
		}

		return sinsp_filter_check::parse_field_name(str, alloc_state, needed_for_filtering);
	}
	else
	{
		return sinsp_filter_check::parse_field_name(str, alloc_state, needed_for_filtering);
	}
}

uint64_t sinsp_filter_check_thread::extract_exectime(sinsp_evt *evt)
{
	uint64_t res = 0;

	if(m_last_proc_switch_times.size() == 0)
	{
		//
		// Initialize the vector of CPU times
		//
		const scap_machine_info* minfo = m_inspector->get_machine_info();
		ASSERT(minfo->num_cpus != 0);

		for(uint32_t j = 0; j < minfo->num_cpus; j++)
		{
			m_last_proc_switch_times.push_back(0);
		}
	}

	uint32_t cpuid = evt->get_cpuid();
	uint64_t ts = evt->get_ts();
	uint64_t lasttime = m_last_proc_switch_times[cpuid];

	if(lasttime != 0)
	{
		res = ts - lasttime;
	}

	ASSERT(cpuid < m_last_proc_switch_times.size());

	m_last_proc_switch_times[cpuid] = ts;

	return res;
}

uint8_t* sinsp_filter_check_thread::extract_thread_cpu(sinsp_evt *evt, OUT uint32_t* len, sinsp_threadinfo* tinfo, bool extract_user, bool extract_system)
{
	uint16_t etype = evt->get_type();

	if(etype == PPME_PROCINFO_E)
	{
		uint64_t user = 0;
		uint64_t system = 0;
		uint64_t tcpu;

		if(extract_user)
		{
			sinsp_evt_param* parinfo = evt->get_param(0);
			user = *(uint64_t*)parinfo->m_val;
		}

		if(extract_system)
		{
			sinsp_evt_param* parinfo = evt->get_param(1);
			system = *(uint64_t*)parinfo->m_val;
		}

		tcpu = user + system;

		uint64_t* last_t_tot_cpu = (uint64_t*)tinfo->get_private_state(m_th_state_id);
		if(*last_t_tot_cpu != 0)
		{
			uint64_t deltaval = tcpu - *last_t_tot_cpu;
			m_dval = (double)deltaval;// / (ONE_SECOND_IN_NS / 100);
			if(m_dval > 100)
			{
				m_dval = 100;
			}
		}
		else
		{
			m_dval = 0;
		}

		*last_t_tot_cpu = tcpu;

		RETURN_EXTRACT_VAR(m_dval);
	}

	return NULL;
}

uint8_t* sinsp_filter_check_thread::extract(sinsp_evt *evt, OUT uint32_t* len, bool sanitize_strings)
{
	*len = 0;
	sinsp_threadinfo* tinfo = evt->get_thread_info();

	if(tinfo == NULL &&
		m_field_id != TYPE_TID &&
		m_field_id != TYPE_EXECTIME &&
		m_field_id != TYPE_TOTEXECTIME)
	{
		return NULL;
	}

	switch(m_field_id)
	{
	case TYPE_TID:
		m_u64val = evt->get_tid();
		RETURN_EXTRACT_VAR(m_u64val);
	case TYPE_PID:
		RETURN_EXTRACT_VAR(tinfo->m_pid);
	case TYPE_SID:
		RETURN_EXTRACT_VAR(tinfo->m_sid);
	case TYPE_VPGID:
		RETURN_EXTRACT_VAR(tinfo->m_vpgid);
	case TYPE_SNAME:
		{
			//
			// Relying on the convention that a session id is the process id of the session leader
			//
			sinsp_threadinfo* sinfo =
				m_inspector->get_thread_ref(tinfo->m_sid, false, true).get();

			if(sinfo != NULL)
			{
				m_tstr = sinfo->get_comm();
				RETURN_EXTRACT_STRING(m_tstr);
			}
			else
			{
				// This can occur when the session leader process has exited.
				// Find the highest ancestor process that has the same session id and
				// declare it to be the session leader.
				sinsp_threadinfo* mt = tinfo->get_main_thread();

				if(mt == NULL)
				{
					return NULL;
				}

				int64_t sid = mt->m_sid;
				sinsp_threadinfo::visitor_func_t visitor = [sid, &mt] (sinsp_threadinfo *pt)
				{
					if(pt->m_sid != sid)
					{
						return false;
					}
					mt = pt;
					return true;
				};

				mt->traverse_parent_state(visitor);

				// mt has been updated to the highest process that has the same session id.
				// mt's comm is considered the session leader.
				m_tstr = mt->get_comm();
				RETURN_EXTRACT_STRING(m_tstr);
			}
		}
	case TYPE_TTY:
		RETURN_EXTRACT_VAR(tinfo->m_tty);
	case TYPE_NAME:
		m_tstr = tinfo->get_comm();
		RETURN_EXTRACT_STRING(m_tstr);
	case TYPE_EXE:
		m_tstr = tinfo->get_exe();
		RETURN_EXTRACT_STRING(m_tstr);
	case TYPE_EXEPATH:
		m_tstr = tinfo->get_exepath();
		RETURN_EXTRACT_STRING(m_tstr);
	case TYPE_ARGS:
		{
			m_tstr.clear();

			uint32_t j;
			uint32_t nargs = (uint32_t)tinfo->m_args.size();

			for(j = 0; j < nargs; j++)
			{
				m_tstr += tinfo->m_args[j];
				if(j < nargs -1)
				{
					m_tstr += ' ';
				}
			}

			RETURN_EXTRACT_STRING(m_tstr);
		}
	case TYPE_ENV:
		{
			m_tstr.clear();

			uint32_t j;
			const auto& env = tinfo->get_env();
			uint32_t nargs = (uint32_t)env.size();

			for(j = 0; j < nargs; j++)
			{
				m_tstr += env[j];
				if(j < nargs -1)
				{
					m_tstr += ' ';
				}
			}

			RETURN_EXTRACT_STRING(m_tstr);
		}
	case TYPE_CMDLINE:
		{
			sinsp_threadinfo::populate_cmdline(m_tstr, tinfo);
			RETURN_EXTRACT_STRING(m_tstr);
		}
	case TYPE_EXELINE:
		{
			m_tstr = tinfo->get_exe() + " ";

			uint32_t j;
			uint32_t nargs = (uint32_t)tinfo->m_args.size();

			for(j = 0; j < nargs; j++)
			{
				m_tstr += tinfo->m_args[j];
				if(j < nargs -1)
				{
					m_tstr += ' ';
				}
			}

			RETURN_EXTRACT_STRING(m_tstr);
		}
	case TYPE_CWD:
		m_tstr = tinfo->get_cwd();
		RETURN_EXTRACT_STRING(m_tstr);
	case TYPE_NTHREADS:
		{
			sinsp_threadinfo* ptinfo = tinfo->get_main_thread();
			if(ptinfo)
			{
				m_u64val = ptinfo->m_nchilds + 1;
				RETURN_EXTRACT_VAR(m_u64val);
			}
			else
			{
				ASSERT(false);
				return NULL;
			}
		}
	case TYPE_NCHILDS:
		RETURN_EXTRACT_VAR(tinfo->m_nchilds);
	case TYPE_ISMAINTHREAD:
		m_tbool = (uint32_t)tinfo->is_main_thread();
		RETURN_EXTRACT_VAR(m_tbool);
	case TYPE_EXECTIME:
		{
			m_u64val = 0;
			uint16_t etype = evt->get_type();

			if(etype == PPME_SCHEDSWITCH_1_E || etype == PPME_SCHEDSWITCH_6_E)
			{
				m_u64val = extract_exectime(evt);
			}

			RETURN_EXTRACT_VAR(m_u64val);
		}
	case TYPE_TOTEXECTIME:
		{
			m_u64val = 0;
			uint16_t etype = evt->get_type();

			if(etype == PPME_SCHEDSWITCH_1_E || etype == PPME_SCHEDSWITCH_6_E)
			{
				m_u64val = extract_exectime(evt);
			}

			sinsp_threadinfo* tinfo = evt->get_thread_info(false);

			if(tinfo != NULL)
			{
				uint64_t* ptot = (uint64_t*)tinfo->get_private_state(m_th_state_id);
				*ptot += m_u64val;
				RETURN_EXTRACT_PTR(ptot);
			}
			else
			{
				return NULL;
			}
		}
	case TYPE_PPID:
		if(tinfo->is_main_thread())
		{
			RETURN_EXTRACT_VAR(tinfo->m_ptid);
		}
		else
		{
			sinsp_threadinfo* mt = tinfo->get_main_thread();

			if(mt != NULL)
			{
				RETURN_EXTRACT_VAR(mt->m_ptid);
			}
			else
			{
				return NULL;
			}
		}
	case TYPE_PNAME:
		{
			sinsp_threadinfo* ptinfo =
				m_inspector->get_thread_ref(tinfo->m_ptid, false, true).get();

			if(ptinfo != NULL)
			{
				m_tstr = ptinfo->get_comm();
				RETURN_EXTRACT_STRING(m_tstr);
			}
			else
			{
				return NULL;
			}
		}
	case TYPE_PCMDLINE:
		{
			sinsp_threadinfo* ptinfo =
				m_inspector->get_thread_ref(tinfo->m_ptid, false, true).get();

			if(ptinfo != NULL)
			{
				sinsp_threadinfo::populate_cmdline(m_tstr, ptinfo);
				RETURN_EXTRACT_STRING(m_tstr);
			}
			else
			{
				return NULL;
			}
		}
	case TYPE_APID:
		{
			sinsp_threadinfo* mt = NULL;

			if(tinfo->is_main_thread())
			{
				mt = tinfo;
			}
			else
			{
				mt = tinfo->get_main_thread();

				if(mt == NULL)
				{
					return NULL;
				}
			}

			//
			// Search for a specific ancestors
			//
			for(int32_t j = 0; j < m_argid; j++)
			{
				mt = mt->get_parent_thread();

				if(mt == NULL)
				{
					return NULL;
				}
			}

			RETURN_EXTRACT_VAR(mt->m_pid);
		}
	case TYPE_ANAME:
		{
			sinsp_threadinfo* mt = NULL;

			if(tinfo->is_main_thread())
			{
				mt = tinfo;
			}
			else
			{
				mt = tinfo->get_main_thread();

				if(mt == NULL)
				{
					return NULL;
				}
			}

			for(int32_t j = 0; j < m_argid; j++)
			{
				mt = mt->get_parent_thread();

				if(mt == NULL)
				{
					return NULL;
				}
			}

			m_tstr = mt->get_comm();
			RETURN_EXTRACT_STRING(m_tstr);
		}
	case TYPE_LOGINSHELLID:
		{
			sinsp_threadinfo* mt = NULL;
			int64_t* res = NULL;

			if(tinfo->is_main_thread())
			{
				mt = tinfo;
			}
			else
			{
				mt = tinfo->get_main_thread();

				if(mt == NULL)
				{
					return NULL;
				}
			}

			sinsp_threadinfo::visitor_func_t check_thread_for_shell = [&res] (sinsp_threadinfo *pt)
			{
				size_t len = pt->m_comm.size();

				if(len >= 2 && pt->m_comm[len - 2] == 's' && pt->m_comm[len - 1] == 'h')
				{
					res = &pt->m_pid;
				}

				return true;
			};

			// First call the visitor on the main thread.
			check_thread_for_shell(mt);

			// Then check all its parents to see if they are shells
			mt->traverse_parent_state(check_thread_for_shell);

			RETURN_EXTRACT_PTR(res);
		}
	case TYPE_DURATION:
		if(tinfo->m_clone_ts != 0)
		{
			m_s64val = evt->get_ts() - tinfo->m_clone_ts;
			ASSERT(m_s64val > 0);
			RETURN_EXTRACT_VAR(m_s64val);
		}
		else
		{
			return NULL;
		}
	case TYPE_FDOPENCOUNT:
		m_u64val = tinfo->get_fd_opencount();
		RETURN_EXTRACT_VAR(m_u64val);
	case TYPE_FDLIMIT:
		m_s64val = tinfo->get_fd_limit();
		RETURN_EXTRACT_VAR(m_s64val);
	case TYPE_FDUSAGE:
		m_dval = tinfo->get_fd_usage_pct_d();
		RETURN_EXTRACT_VAR(m_dval);
	case TYPE_VMSIZE:
		m_u64val = tinfo->m_vmsize_kb;
		RETURN_EXTRACT_VAR(m_u64val);
	case TYPE_VMRSS:
		m_u64val = tinfo->m_vmrss_kb;
		RETURN_EXTRACT_VAR(m_u64val);
	case TYPE_VMSWAP:
		m_u64val = tinfo->m_vmswap_kb;
		RETURN_EXTRACT_VAR(m_u64val);
	case TYPE_THREAD_VMSIZE:
		if(tinfo->is_main_thread())
		{
			m_u64val = tinfo->m_vmsize_kb;
		}
		else
		{
			m_u64val = 0;
		}

		RETURN_EXTRACT_VAR(m_u64val);
	case TYPE_THREAD_VMRSS:
		if(tinfo->is_main_thread())
		{
			m_u64val = tinfo->m_vmrss_kb;
		}
		else
		{
			m_u64val = 0;
		}

		RETURN_EXTRACT_VAR(m_u64val);
	case TYPE_THREAD_VMSIZE_B:
		if(tinfo->is_main_thread())
		{
			m_u64val = tinfo->m_vmsize_kb * 1024;
		}
		else
		{
			m_u64val = 0;
		}

		RETURN_EXTRACT_VAR(m_u64val);
	case TYPE_THREAD_VMRSS_B:
		if(tinfo->is_main_thread())
		{
			m_u64val = tinfo->m_vmrss_kb * 1024;
		}
		else
		{
			m_u64val = 0;
		}

		RETURN_EXTRACT_VAR(m_u64val);
	case TYPE_PFMAJOR:
		m_u64val = tinfo->m_pfmajor;
		RETURN_EXTRACT_VAR(m_u64val);
	case TYPE_PFMINOR:
		m_u64val = tinfo->m_pfminor;
		RETURN_EXTRACT_VAR(m_u64val);
	case TYPE_CGROUPS:
		{
			m_tstr.clear();

			uint32_t j;
			uint32_t nargs = (uint32_t)tinfo->m_cgroups.size();

			if(nargs == 0)
			{
				return NULL;
			}

			for(j = 0; j < nargs; j++)
			{
				m_tstr += tinfo->m_cgroups[j].first;
				m_tstr += "=";
				m_tstr += tinfo->m_cgroups[j].second;
				if(j < nargs - 1)
				{
					m_tstr += ' ';
				}
			}

			RETURN_EXTRACT_STRING(m_tstr);
		}
	case TYPE_CGROUP:
		{
			uint32_t nargs = (uint32_t)tinfo->m_cgroups.size();

			if(nargs == 0)
			{
				return NULL;
			}

			for(uint32_t j = 0; j < nargs; j++)
			{
				if(tinfo->m_cgroups[j].first == m_argname)
				{
					m_tstr = tinfo->m_cgroups[j].second;
					RETURN_EXTRACT_STRING(m_tstr);
				}
			}

			return NULL;
		}
	case TYPE_VTID:
		if(tinfo->m_vtid == -1)
		{
			return NULL;
		}

		m_u64val = tinfo->m_vtid;
		RETURN_EXTRACT_VAR(m_u64val);
	case TYPE_VPID:
		if(tinfo->m_vpid == -1)
		{
			return NULL;
		}

		m_u64val = tinfo->m_vpid;
		RETURN_EXTRACT_VAR(m_u64val);
/*
	case TYPE_PROC_CPU:
		{
			uint16_t etype = evt->get_type();

			if(etype == PPME_PROCINFO_E)
			{
				double thval;
				uint64_t tcpu;

				sinsp_evt_param* parinfo = evt->get_param(0);
				tcpu = *(uint64_t*)parinfo->m_val;

				parinfo = evt->get_param(1);
				tcpu += *(uint64_t*)parinfo->m_val;

				if(tinfo->m_last_t_tot_cpu != 0)
				{
					uint64_t deltaval = tcpu - tinfo->m_last_t_tot_cpu;
					thval = (double)deltaval;// / (ONE_SECOND_IN_NS / 100);
					if(thval > 100)
					{
						thval = 100;
					}
				}
				else
				{
					thval = 0;
				}

				tinfo->m_last_t_tot_cpu = tcpu;

				uint64_t ets = evt->get_ts();
				sinsp_threadinfo* mt = tinfo->get_main_thread();

				if(ets != mt->m_last_mt_cpu_ts)
				{
					mt->m_last_mt_tot_cpu = 0;
					mt->m_last_mt_cpu_ts = ets;
				}

				mt->m_last_mt_tot_cpu += thval;
				m_dval = mt->m_last_mt_tot_cpu;

				RETURN_EXTRACT_VAR(m_dval);
			}

			return NULL;
		}
*/
	case TYPE_THREAD_CPU:
		{
			return extract_thread_cpu(evt, len, tinfo, true, true);
		}
	case TYPE_THREAD_CPU_USER:
		{
			return extract_thread_cpu(evt, len, tinfo, true, false);
		}
	case TYPE_THREAD_CPU_SYSTEM:
		{
			return extract_thread_cpu(evt, len, tinfo, false, true);
		}
	case TYPE_NAMETID:
		m_tstr = tinfo->get_comm() + to_string(evt->get_tid());
		RETURN_EXTRACT_STRING(m_tstr);
	case TYPE_IS_CONTAINER_HEALTHCHECK:
		m_tbool = (tinfo->m_category == sinsp_threadinfo::CAT_HEALTHCHECK);
		RETURN_EXTRACT_VAR(m_tbool);
	case TYPE_IS_CONTAINER_LIVENESS_PROBE:
		m_tbool = (tinfo->m_category == sinsp_threadinfo::CAT_LIVENESS_PROBE);
		RETURN_EXTRACT_VAR(m_tbool);
	case TYPE_IS_CONTAINER_READINESS_PROBE:
		m_tbool = (tinfo->m_category == sinsp_threadinfo::CAT_READINESS_PROBE);
		RETURN_EXTRACT_VAR(m_tbool);
	case TYPE_IS_EXE_WRITABLE:
		m_tbool = tinfo->m_exe_writable;
		RETURN_EXTRACT_VAR(m_tbool);
	default:
		ASSERT(false);
		return NULL;
	}
}

bool sinsp_filter_check_thread::compare_full_apid(sinsp_evt *evt)
{
	sinsp_threadinfo* tinfo = evt->get_thread_info();

	if(tinfo == NULL)
	{
		return false;
	}

	sinsp_threadinfo* mt = NULL;

	if(tinfo->is_main_thread())
	{
		mt = tinfo;
	}
	else
	{
		mt = tinfo->get_main_thread();

		if(mt == NULL)
		{
			return false;
		}
	}

	//
	// No id specified, search in all of the ancestors
	//
	bool found = false;
	sinsp_threadinfo::visitor_func_t visitor = [this, &found] (sinsp_threadinfo *pt)
	{
		bool res;

		res = flt_compare(m_cmpop,
				  PT_PID,
				  &pt->m_pid);

		if(res == true)
		{
			found = true;

			// Can stop traversing parent state
			return false;
		}

		return true;
	};

	mt->traverse_parent_state(visitor);

	return found;
}

bool sinsp_filter_check_thread::compare_full_aname(sinsp_evt *evt)
{
	sinsp_threadinfo* tinfo = evt->get_thread_info();

	if(tinfo == NULL)
	{
		return false;
	}

	sinsp_threadinfo* mt = NULL;

	if(tinfo->is_main_thread())
	{
		mt = tinfo;
	}
	else
	{
		mt = tinfo->get_main_thread();

		if(mt == NULL)
		{
			return false;
		}
	}

	//
	// No id specified, search in all of the ancestors
	//
	bool found = false;
	sinsp_threadinfo::visitor_func_t visitor = [this, &found] (sinsp_threadinfo *pt)
	{
		bool res;

		res = flt_compare(m_cmpop,
				  PT_CHARBUF,
				  (void*)pt->m_comm.c_str());

		if(res == true)
		{
			found = true;

			// Can stop traversing parent state
			return false;
		}

		return true;
	};

	mt->traverse_parent_state(visitor);

	return found;
}

bool sinsp_filter_check_thread::compare(sinsp_evt *evt)
{
	if(m_field_id == TYPE_APID)
	{
		if(m_argid == -1)
		{
			return compare_full_apid(evt);
		}
	}
	else if(m_field_id == TYPE_ANAME)
	{
		if(m_argid == -1)
		{
			return compare_full_aname(evt);
		}
	}

	return sinsp_filter_check::compare(evt);
}
