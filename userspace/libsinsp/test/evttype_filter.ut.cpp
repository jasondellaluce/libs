/*
Copyright (C) 2021 The Falco Authors.

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

#include <gtest.h>
#include <sinsp.h>
#include <filter.h>

std::stringstream & operator<<(std::stringstream &out, set<uint16_t> s)
{
	out << "[ ";
	for(auto &val : s)
	{
		out << val;
		out << " ";
	}
	out << "]";

	return out;
}

class evttype_filter_test : public testing::Test
{

protected:

	void SetUp()
	{
		for(uint32_t i = 0; i < PPM_EVENT_MAX; i++)
		{
			if(openat_only.find(i) == openat_only.end())
			{
				not_openat.insert(i);
			}

			if(openat_only.find(i) == openat_only.end() ||
			   close_only.find(i) == close_only.end())

			{
				not_openat_close.insert(i);
			}
		}

		not_openat.insert(PPME_GENERIC_E);
		not_openat.insert(PPME_GENERIC_X);

		not_openat_close.insert(PPME_GENERIC_E);
		not_openat_close.insert(PPME_GENERIC_X);
	}

	void TearDown()
	{
	}

	sinsp_filter *compile(const string &fltstr)
	{
		sinsp_filter_compiler compiler(NULL, fltstr);

		return compiler.compile();
	}

	void compare_evttypes(sinsp_filter *f, std::set<uint16_t> expected)
	{
		std::set<uint16_t> actual = f->evttypes();

		for(auto &etype : expected)
		{
			if(actual.find(etype) == actual.end())
			{
				FAIL() << "Expected event type "
				       << etype
				       << " not found in actual set. "
				       << "Expected: " << expected
				       << " Actual: " << actual;

			}
		}

		for(auto &etype : actual)
		{
			if(expected.find(etype) == expected.end())
			{
				FAIL() << "Actual evttypes had additional event type "
				       << etype
				       << " not found in expected set. "
				       << "Expected: " << expected
				       << " Actual: " << actual;
			}
		}
	}

	std::set<uint16_t> openat_only{
		PPME_SYSCALL_OPENAT_E, PPME_SYSCALL_OPENAT_X,
		PPME_SYSCALL_OPENAT_2_E, PPME_SYSCALL_OPENAT_2_X,
		PPME_GENERIC_E, PPME_GENERIC_X};

	std::set<uint16_t> close_only{
		PPME_SYSCALL_CLOSE_E, PPME_SYSCALL_CLOSE_X,
		PPME_GENERIC_E, PPME_GENERIC_X};

	std::set<uint16_t> openat_close{
		PPME_SYSCALL_OPENAT_E, PPME_SYSCALL_OPENAT_X,
		PPME_SYSCALL_OPENAT_2_E, PPME_SYSCALL_OPENAT_2_X,
		PPME_SYSCALL_CLOSE_E, PPME_SYSCALL_CLOSE_X,
		PPME_GENERIC_E, PPME_GENERIC_X};

	std::set<uint16_t> not_openat;

	std::set<uint16_t> not_openat_close;

	std::set<uint16_t> empty;

};

TEST_F(evttype_filter_test, evt_type_eq)
{
	sinsp_filter *f = compile("evt.type=openat");

	compare_evttypes(f, openat_only);
}

TEST_F(evttype_filter_test, evt_type_in)
{
	sinsp_filter *f = compile("evt.type in (openat, close)");

	compare_evttypes(f, openat_close);
}

TEST_F(evttype_filter_test, evt_type_ne)
{
	sinsp_filter *f = compile("evt.type!=openat");

	compare_evttypes(f, not_openat);
}

TEST_F(evttype_filter_test, not_evt_type_eq)
{
	sinsp_filter *f = compile("not evt.type=openat");

	compare_evttypes(f, not_openat);
}

TEST_F(evttype_filter_test, not_evt_type_in)
{
	sinsp_filter *f = compile("not evt.type in (openat, close)");

	compare_evttypes(f, not_openat_close);
}

TEST_F(evttype_filter_test, not_evt_type_ne)
{
	sinsp_filter *f = compile("not evt.type != openat");

	compare_evttypes(f, openat_only);
}

TEST_F(evttype_filter_test, evt_type_or)
{
	sinsp_filter *f = compile("evt.type=openat or evt.type=close");

	compare_evttypes(f, openat_close);
}

TEST_F(evttype_filter_test, not_evt_type_or)
{
	sinsp_filter *f = compile("evt.type!=openat or evt.type!=close");

	compare_evttypes(f, not_openat_close);
}

TEST_F(evttype_filter_test, evt_type_or_ne)
{
	sinsp_filter *f = compile("evt.type=close or evt.type!=openat");

	compare_evttypes(f, not_openat);
}

TEST_F(evttype_filter_test, evt_type_and)
{
	sinsp_filter *f = compile("evt.type=close and evt.type=openat");

	compare_evttypes(f, openat_close);
}

TEST_F(evttype_filter_test, evt_type_and_non_evt_type)
{
	sinsp_filter *f = compile("evt.type=openat and proc.name=nginx");

	compare_evttypes(f, openat_only);
}


TEST_F(evttype_filter_test, non_evt_type)
{
	sinsp_filter *f = compile("proc.name=nginx");

	compare_evttypes(f, empty);
}
