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

#pragma once

#include <set>
#include <vector>

#ifdef HAS_FILTERING

#include "filter_check_list.h"
#include "gen_filter.h"
#include "filter/parser.h"

/** @defgroup filter Filtering events
 * Filtering infrastructure.
 *  @{
 */

/*!
  \brief This is the class that runs the filters.
*/
class SINSP_PUBLIC sinsp_filter : public gen_event_filter
{
public:
	sinsp_filter(sinsp* inspector);
	~sinsp_filter();

private:
	sinsp* m_inspector;

	friend class sinsp_evt_formatter;
};


/*!
  \brief This is the class that compiles the filters.
*/
class SINSP_PUBLIC sinsp_filter_compiler: 
	private libsinsp::filter::ast::expr_visitor
{
public:
	/*!
		\brief Constructs the compiler

		\param inspector Pointer to the inspector instance that will generate
		the events to be filtered
		\param fltstr The filter string to compile
		\param ttable_only For internal use only

		\note This is not the primary constructor, and is only maintained for
		backward compatibility
	*/
	sinsp_filter_compiler(
		sinsp* inspector,
		const string& fltstr,
		bool ttable_only=false);

	/*!
		\brief Constructs the compiler

		\param factory Pointer to a filter factory to be used to build
		the filtercheck tree
		\param fltstr The filter string to compile
		\param ttable_only For internal use only
	*/
	sinsp_filter_compiler(
		std::shared_ptr<gen_event_filter_factory> factory,
		const string& fltstr,
		bool ttable_only=false);

	/*!
		\brief Constructs the compiler

		\param factory Pointer to a filter factory to be used to build
		the filtercheck tree
		\param fltast AST of a parsed filter, used to build the filtercheck
		tree
		\param ttable_only For internal use only
	*/
	sinsp_filter_compiler(
		std::shared_ptr<gen_event_filter_factory> factory,
		libsinsp::filter::ast::expr* fltast,
		bool ttable_only=false);

	~sinsp_filter_compiler();

	/*!
		\brief Builds a filtercheck tree and bundles it in sinsp_filter
		\return The resulting pointer is owned by the caller and must be deleted
		by it. The pointer is automatically deleted in case of exception.
		\note Throws a sinsp_exception if the filter syntax is not valid
	*/
	sinsp_filter* compile();

	void set_check_id(int32_t id);

private:
	void visit(libsinsp::filter::ast::and_expr&) override;
	void visit(libsinsp::filter::ast::or_expr&) override;
	void visit(libsinsp::filter::ast::not_expr&) override;
	void visit(libsinsp::filter::ast::value_expr&) override;
	void visit(libsinsp::filter::ast::list_expr&) override;
	void visit(libsinsp::filter::ast::unary_check_expr&) override;
	void visit(libsinsp::filter::ast::binary_check_expr&) override;
	void check_ttable_only(string& field, gen_event_filter_check *check);
	cmpop str_to_cmpop(string& str);
	string create_filtercheck_name(string& name, string& arg);
	gen_event_filter_check* create_filtercheck(string& field);

	int32_t m_check_id;
	bool m_ttable_only;
	bool m_internal_parsing;
	bool m_expect_values;
	boolop m_last_boolop;
	string m_flt_str;
	sinsp_filter* m_filter;
	vector<string> m_field_values;
	libsinsp::filter::ast::expr* m_flt_ast;
	std::shared_ptr<gen_event_filter_factory> m_factory;

	friend class sinsp_evt_formatter;
};

/*!
  \brief This class represents a filter optimized using event
  types. It actually consists of collections of sinsp_filter objects
  grouped by event type.
*/

class SINSP_PUBLIC sinsp_evttype_filter
{
public:
	sinsp_evttype_filter();
	virtual ~sinsp_evttype_filter();

	void add(std::string &name,
		 std::set<uint32_t> &evttypes,
		 std::set<uint32_t> &syscalls,
		 std::set<string> &tags,
		 sinsp_filter* filter);

	// rulesets are arbitrary numbers and should be managed by the caller.
        // Note that rulesets are used to index into a std::vector so
        // specifying unnecessarily large rulesets will result in
        // unnecessarily large vectors.

	// Find those rules matching the provided pattern and set
	// their enabled status to enabled.
	void enable(const std::string &pattern, bool enabled, uint16_t ruleset = 0);

	// Find those rules that have a tag in the set of tags and set
	// their enabled status to enabled. Note that the enabled
	// status is on the rules, and not the tags--if a rule R has
	// tags (a, b), and you call enable_tags([a], true) and then
	// enable_tags([b], false), R will be disabled despite the
	// fact it has tag a and was enabled by the first call to
	// enable_tags.
	void enable_tags(const std::set<string> &tags, bool enabled, uint16_t ruleset = 0);

	// Match all filters against the provided event.
	bool run(sinsp_evt *evt, uint16_t ruleset = 0);

	// Populate the provided vector, indexed by event type, of the
	// event types associated with the given ruleset id. For
	// example, evttypes[10] = true would mean that this ruleset
	// relates to event type 10.
	void evttypes_for_ruleset(std::vector<bool> &evttypes, uint16_t ruleset);

	// Populate the provided vector, indexed by syscall code, of the
	// syscall codes associated with the given ruleset id. For
	// example, syscalls[10] = true would mean that this ruleset
	// relates to syscall code 10.
	void syscalls_for_ruleset(std::vector<bool> &syscalls, uint16_t ruleset);

private:

	struct filter_wrapper {
		sinsp_filter *filter;

		// Indexes from event type to enabled/disabled.
		std::vector<bool> evttypes;

		// Indexes from syscall code to enabled/disabled.
		std::vector<bool> syscalls;
	};

	// A group of filters all having the same ruleset
	class ruleset_filters {
	public:
		ruleset_filters();

		virtual ~ruleset_filters();

		void add_filter(filter_wrapper *wrap);
		void remove_filter(filter_wrapper *wrap);

		bool run(sinsp_evt *evt);

		void evttypes_for_ruleset(std::vector<bool> &evttypes);

		void syscalls_for_ruleset(std::vector<bool> &syscalls);

	private:
		// Maps from event type to filter. There can be multiple
		// filters per event type.
		std::list<filter_wrapper *> *m_filter_by_evttype[PPM_EVENT_MAX];

		// Maps from syscall number to filter. There can be multiple
		// filters per syscall number
		std::list<filter_wrapper *> *m_filter_by_syscall[PPM_SC_MAX];
	};

	std::vector<ruleset_filters *> m_rulesets;

	// Maps from tag to list of filters having that tag.
	std::map<std::string, std::list<filter_wrapper *>> m_filter_by_tag;

	// This holds all the filters passed to add(), so they can
	// be cleaned up.
	map<std::string,filter_wrapper *> m_filters;
};

/*@}*/

class sinsp_filter_factory : public gen_event_filter_factory
{
public:
	sinsp_filter_factory(sinsp *inspector, filter_check_list &available_checks=g_filterlist);

	virtual ~sinsp_filter_factory();

	gen_event_filter *new_filter();

	gen_event_filter_check *new_filtercheck(const char *fldname);

	std::list<gen_event_filter_factory::filter_fieldclass_info> get_fields() override;

	// Convienence method to convert a vector of
	// filter_check_infos into a list of
	// filter_fieldclass_infos. This is useful for programs that
	// use filterchecks but not factories.
	static std::list<filter_fieldclass_info> check_infos_to_fieldclass_infos(
		const vector<const filter_check_info*> &fc_plugins);

protected:
	sinsp *m_inspector;
	filter_check_list &m_available_checks;
};

#endif // HAS_FILTERING
