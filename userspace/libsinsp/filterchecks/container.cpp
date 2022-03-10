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
#include "container.h"

///////////////////////////////////////////////////////////////////////////////
// sinsp_filter_check_container implementation
///////////////////////////////////////////////////////////////////////////////
const filtercheck_field_info sinsp_filter_check_container_fields[] =
{
	{PT_CHARBUF, EPF_NONE, PF_NA, "container.id", "Container ID", "the container id."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "container.name", "Container Name", "the container name."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "container.image", "Image Name", "the container image name (e.g. falcosecurity/falco:latest for docker)."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "container.image.id", "Image ID", "the container image id (e.g. 6f7e2741b66b)."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "container.type", "Type", "the container type, eg: docker or rkt"},
	{PT_BOOL, EPF_NONE, PF_NA, "container.privileged", "Privileged", "true for containers running as privileged, false otherwise"},
	{PT_CHARBUF, EPF_NONE, PF_NA, "container.mounts", "Mounts", "A space-separated list of mount information. Each item in the list has the format <source>:<dest>:<mode>:<rdrw>:<propagation>"},
	{PT_CHARBUF, EPF_REQUIRES_ARGUMENT, PF_NA, "container.mount", "Mount", "Information about a single mount, specified by number (e.g. container.mount[0]) or mount source (container.mount[/usr/local]). The pathname can be a glob (container.mount[/usr/local/*]), in which case the first matching mount will be returned. The information has the format <source>:<dest>:<mode>:<rdrw>:<propagation>. If there is no mount with the specified index or matching the provided source, returns the string \"none\" instead of a NULL value."},
	{PT_CHARBUF, EPF_REQUIRES_ARGUMENT, PF_NA, "container.mount.source", "Mount Source", "the mount source, specified by number (e.g. container.mount.source[0]) or mount destination (container.mount.source[/host/lib/modules]). The pathname can be a glob."},
	{PT_CHARBUF, EPF_REQUIRES_ARGUMENT, PF_NA, "container.mount.dest", "Mount Destination", "the mount destination, specified by number (e.g. container.mount.dest[0]) or mount source (container.mount.dest[/lib/modules]). The pathname can be a glob."},
	{PT_CHARBUF, EPF_REQUIRES_ARGUMENT, PF_NA, "container.mount.mode", "Mount Mode", "the mount mode, specified by number (e.g. container.mount.mode[0]) or mount source (container.mount.mode[/usr/local]). The pathname can be a glob."},
	{PT_CHARBUF, EPF_REQUIRES_ARGUMENT, PF_NA, "container.mount.rdwr", "Mount Read/Write", "the mount rdwr value, specified by number (e.g. container.mount.rdwr[0]) or mount source (container.mount.rdwr[/usr/local]). The pathname can be a glob."},
	{PT_CHARBUF, EPF_REQUIRES_ARGUMENT, PF_NA, "container.mount.propagation", "Mount Propagation", "the mount propagation value, specified by number (e.g. container.mount.propagation[0]) or mount source (container.mount.propagation[/usr/local]). The pathname can be a glob."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "container.image.repository", "Repository", "the container image repository (e.g. falcosecurity/falco)."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "container.image.tag", "Image Tag", "the container image tag (e.g. stable, latest)."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "container.image.digest", "Registry Digest", "the container image registry digest (e.g. sha256:d977378f890d445c15e51795296e4e5062f109ce6da83e0a355fc4ad8699d27)."},
	{PT_CHARBUF, EPF_NONE, PF_NA, "container.healthcheck", "Health Check", "The container's health check. Will be the null value (\"N/A\") if no healthcheck configured, \"NONE\" if configured but explicitly not created, and the healthcheck command line otherwise"},
	{PT_CHARBUF, EPF_NONE, PF_NA, "container.liveness_probe", "Liveness", "The container's liveness probe. Will be the null value (\"N/A\") if no liveness probe configured, the liveness probe command line otherwise"},
	{PT_CHARBUF, EPF_NONE, PF_NA, "container.readiness_probe", "Readiness", "The container's readiness probe. Will be the null value (\"N/A\") if no readiness probe configured, the readiness probe command line otherwise"}
};

sinsp_filter_check_container::sinsp_filter_check_container()
{
	m_info.m_name = "container";
	m_info.m_desc = "Container information. If the event is not happening inside a container, both id and name will be set to 'host'.";
	m_info.m_fields = sinsp_filter_check_container_fields;
	m_info.m_nfields = sizeof(sinsp_filter_check_container_fields) / sizeof(sinsp_filter_check_container_fields[0]);
	m_info.m_flags = filter_check_info::FL_WORKS_ON_THREAD_TABLE;
}

sinsp_filter_check* sinsp_filter_check_container::allocate_new()
{
	return (sinsp_filter_check*) new sinsp_filter_check_container();
}

int32_t sinsp_filter_check_container::extract_arg(const string &val, size_t basepos)
{
	size_t start = val.find_first_of('[', basepos);
	if(start == string::npos)
	{
		throw sinsp_exception("filter syntax error: " + val);
	}

	size_t end = val.find_first_of(']', start);
	if(end == string::npos)
	{
		throw sinsp_exception("filter syntax error: " + val);
	}

	string numstr = val.substr(start + 1, end-start-1);
	try
	{
		m_argid = sinsp_numparser::parsed32(numstr);
	}
	catch (const sinsp_exception& e)
	{
		if(strstr(e.what(), "is not a valid number") == NULL)
		{
			throw;
		}

		m_argid = -1;
		m_argstr = numstr;
	}

	return end+1;
}

int32_t sinsp_filter_check_container::parse_field_name(const char* str, bool alloc_state, bool needed_for_filtering)
{
	string val(str);
	int32_t res = 0;

	size_t basepos = sizeof("container.mount");

	// container.mount. fields allow for indexing by number or source/dest mount path.
	if(val.find("container.mount.") == 0)
	{
		// Note--basepos includes the trailing null, which is
		// equivalent to the trailing '.' here.
		if(val.find("source", basepos) == basepos)
		{
			m_field_id = TYPE_CONTAINER_MOUNT_SOURCE;
		}
		else if(val.find("dest", basepos) == basepos)
		{
			m_field_id = TYPE_CONTAINER_MOUNT_DEST;
		}
		else if(val.find("mode", basepos) == basepos)
		{
			m_field_id = TYPE_CONTAINER_MOUNT_MODE;
		}
		else if(val.find("rdwr", basepos) == basepos)
		{
			m_field_id = TYPE_CONTAINER_MOUNT_RDWR;
		}
		else if(val.find("propagation", basepos) == basepos)
		{
			m_field_id = TYPE_CONTAINER_MOUNT_PROPAGATION;
		}
		else
		{
			throw sinsp_exception("filter syntax error: " + val);
		}
		m_field = &m_info.m_fields[m_field_id];

		res = extract_arg(val, basepos);
	}
	else if (val.find("container.mount") == 0 &&
		 val[basepos-1] != 's')
	{
		m_field_id = TYPE_CONTAINER_MOUNT;
		m_field = &m_info.m_fields[m_field_id];

		res = extract_arg(val, basepos-1);
	}
	else
	{
		res = sinsp_filter_check::parse_field_name(str, alloc_state, needed_for_filtering);
	}

	return res;
}


uint8_t* sinsp_filter_check_container::extract(sinsp_evt *evt, OUT uint32_t* len, bool sanitize_strings)
{
	*len = 0;
	sinsp_threadinfo* tinfo = evt->get_thread_info();
	if(tinfo == NULL)
	{
		return NULL;
	}

	switch(m_field_id)
	{
	case TYPE_CONTAINER_ID:
		if(tinfo->m_container_id.empty())
		{
			m_tstr = "host";
		}
		else
		{
			m_tstr = tinfo->m_container_id;
		}

		RETURN_EXTRACT_STRING(m_tstr);
	case TYPE_CONTAINER_NAME:
		if(tinfo->m_container_id.empty())
		{
			m_tstr = "host";
		}
		else
		{
			const sinsp_container_info::ptr_t container_info =
				m_inspector->m_container_manager.get_container(tinfo->m_container_id);
			if(!container_info)
			{
				return NULL;
			}

			if(container_info->m_name.empty())
			{
				return NULL;
			}

			m_tstr = container_info->m_name;
		}

		RETURN_EXTRACT_STRING(m_tstr);
	case TYPE_CONTAINER_IMAGE:
		if(tinfo->m_container_id.empty())
		{
			return NULL;
		}
		else
		{
			const sinsp_container_info::ptr_t container_info =
				m_inspector->m_container_manager.get_container(tinfo->m_container_id);
			if(!container_info)
			{
				return NULL;
			}

			if(container_info->m_image.empty())
			{
				return NULL;
			}

			m_tstr = container_info->m_image;
		}

		RETURN_EXTRACT_STRING(m_tstr);
	case TYPE_CONTAINER_IMAGE_ID:
	case TYPE_CONTAINER_IMAGE_REPOSITORY:
	case TYPE_CONTAINER_IMAGE_TAG:
	case TYPE_CONTAINER_IMAGE_DIGEST:
		if(tinfo->m_container_id.empty())
		{
			return NULL;
		}
		else
		{
			const sinsp_container_info::ptr_t container_info =
				m_inspector->m_container_manager.get_container(tinfo->m_container_id);
			if(!container_info)
			{
				return NULL;
			}

			const string *field;
			switch(m_field_id)
			{
			case TYPE_CONTAINER_IMAGE_ID:
				field = &container_info->m_imageid;
				break;
			case TYPE_CONTAINER_IMAGE_REPOSITORY:
				field = &container_info->m_imagerepo;
				break;
			case TYPE_CONTAINER_IMAGE_TAG:
				field = &container_info->m_imagetag;
				break;
			case TYPE_CONTAINER_IMAGE_DIGEST:
				field = &container_info->m_imagedigest;
				break;
			default:
				break;
			}

			if(field->empty())
			{
				return NULL;
			}

			m_tstr = *field;
		}

		RETURN_EXTRACT_STRING(m_tstr);
	case TYPE_CONTAINER_TYPE:
		if(tinfo->m_container_id.empty())
		{
			m_tstr = "host";
		}
		else
		{
			const sinsp_container_info::ptr_t container_info =
				m_inspector->m_container_manager.get_container(tinfo->m_container_id);
			if(!container_info)
			{
				return NULL;
			}
			switch(container_info->m_type)
			{
			case sinsp_container_type::CT_DOCKER:
				m_tstr = "docker";
				break;
			case sinsp_container_type::CT_LXC:
				m_tstr = "lxc";
				break;
			case sinsp_container_type::CT_LIBVIRT_LXC:
				m_tstr = "libvirt-lxc";
				break;
			case sinsp_container_type::CT_MESOS:
				m_tstr = "mesos";
				break;
			case sinsp_container_type::CT_CRI:
				m_tstr = "cri";
				break;
			case sinsp_container_type::CT_CONTAINERD:
				m_tstr = "containerd";
				break;
			case sinsp_container_type::CT_CRIO:
				m_tstr = "cri-o";
				break;
			case sinsp_container_type::CT_RKT:
				m_tstr = "rkt";
				break;
			case sinsp_container_type::CT_BPM:
				m_tstr = "bpm";
				break;
			default:
				ASSERT(false);
				break;
			}
		}
		RETURN_EXTRACT_STRING(m_tstr);
	case TYPE_CONTAINER_PRIVILEGED:
		if(tinfo->m_container_id.empty())
		{
			return NULL;
		}
		else
		{
			const sinsp_container_info::ptr_t container_info =
				m_inspector->m_container_manager.get_container(tinfo->m_container_id);
			if(!container_info)
			{
				return NULL;
			}

			// Only return a true/false value for
			// container types where we really know the
			// privileged status.
			if (!is_docker_compatible(container_info->m_type))
			{
				return NULL;
			}

			m_u32val = (container_info->m_privileged ? 1 : 0);
		}

		RETURN_EXTRACT_VAR(m_u32val);
		break;
	case TYPE_CONTAINER_MOUNTS:
		if(tinfo->m_container_id.empty())
		{
			return NULL;
		}
		else
		{
			const sinsp_container_info::ptr_t container_info =
				m_inspector->m_container_manager.get_container(tinfo->m_container_id);
			if(!container_info)
			{
				return NULL;
			}

			m_tstr = "";
			bool first = true;
			for(auto &mntinfo : container_info->m_mounts)
			{
				if(first)
				{
					first = false;
				}
				else
				{
					m_tstr += ",";
				}

				m_tstr += mntinfo.to_string();
			}

			RETURN_EXTRACT_STRING(m_tstr);
		}

		break;
	case TYPE_CONTAINER_MOUNT:
		if(tinfo->m_container_id.empty())
		{
			return NULL;
		}
		else
		{

			const sinsp_container_info::ptr_t container_info =
				m_inspector->m_container_manager.get_container(tinfo->m_container_id);
			if(!container_info)
			{
				return NULL;
			}

			const sinsp_container_info::container_mount_info *mntinfo;

			if(m_argid != -1)
			{
				mntinfo = container_info->mount_by_idx(m_argid);
			}
			else
			{
				mntinfo = container_info->mount_by_source(m_argstr);
			}

			if(!mntinfo)
			{
				return NULL;
			}
			else
			{
				m_tstr = mntinfo->to_string();
			}

			RETURN_EXTRACT_STRING(m_tstr);
		}

		break;
	case TYPE_CONTAINER_MOUNT_SOURCE:
	case TYPE_CONTAINER_MOUNT_DEST:
	case TYPE_CONTAINER_MOUNT_MODE:
	case TYPE_CONTAINER_MOUNT_RDWR:
	case TYPE_CONTAINER_MOUNT_PROPAGATION:
		if(tinfo->m_container_id.empty())
		{
			return NULL;
		}
		else
		{

			const sinsp_container_info::ptr_t container_info =
				m_inspector->m_container_manager.get_container(tinfo->m_container_id);
			if(!container_info)
			{
				return NULL;
			}

			const sinsp_container_info::container_mount_info *mntinfo;

			if(m_argid != -1)
			{
				mntinfo = container_info->mount_by_idx(m_argid);
			}
			else
			{
				if (m_field_id == TYPE_CONTAINER_MOUNT_SOURCE)
				{
					mntinfo = container_info->mount_by_dest(m_argstr);
				}
				else
				{
					mntinfo = container_info->mount_by_source(m_argstr);
				}
			}

			if(!mntinfo)
			{
				return NULL;
			}

			switch (m_field_id)
			{
			case TYPE_CONTAINER_MOUNT_SOURCE:
				m_tstr = mntinfo->m_source;
				break;
			case TYPE_CONTAINER_MOUNT_DEST:
				m_tstr = mntinfo->m_dest;
				break;
			case TYPE_CONTAINER_MOUNT_MODE:
				m_tstr = mntinfo->m_mode;
				break;
			case TYPE_CONTAINER_MOUNT_RDWR:
				m_tstr = (mntinfo->m_rdwr ? "true" : "false");
				break;
			case TYPE_CONTAINER_MOUNT_PROPAGATION:
				m_tstr = mntinfo->m_propagation;
				break;
			}

			RETURN_EXTRACT_STRING(m_tstr);
		}
		break;
	case TYPE_CONTAINER_HEALTHCHECK:
	case TYPE_CONTAINER_LIVENESS_PROBE:
	case TYPE_CONTAINER_READINESS_PROBE:
		if(tinfo->m_container_id.empty())
		{
			return NULL;
		}
		else
		{
			const sinsp_container_info::ptr_t container_info =
				m_inspector->m_container_manager.get_container(tinfo->m_container_id);
			if(!container_info)
			{
				return NULL;
			}

			for(auto &probe : container_info->m_health_probes)
			{
				if((m_field_id == TYPE_CONTAINER_HEALTHCHECK &&
				    probe.m_probe_type == sinsp_container_info::container_health_probe::PT_HEALTHCHECK) ||
				   (m_field_id == TYPE_CONTAINER_LIVENESS_PROBE &&
				    probe.m_probe_type == sinsp_container_info::container_health_probe::PT_LIVENESS_PROBE) ||
				   (m_field_id == TYPE_CONTAINER_READINESS_PROBE &&
				    probe.m_probe_type == sinsp_container_info::container_health_probe::PT_READINESS_PROBE))
				{
					m_tstr = probe.m_health_probe_exe;

					for(auto &arg : probe.m_health_probe_args)
					{
						m_tstr += " ";
						m_tstr += arg;
					}

					RETURN_EXTRACT_STRING(m_tstr);
				}
			}

			// If here, then the container didn't have any
			// health probe matching the filtercheck
			// field.
			m_tstr = "NONE";
			RETURN_EXTRACT_STRING(m_tstr);
		}

	default:
		ASSERT(false);
		break;
	}

	return NULL;
}
