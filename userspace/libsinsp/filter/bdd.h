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

#include "ast.h"
#include "../sinsp.h"
#include <string>
#include <vector>
#include <set>
#include <unordered_set>

typedef int32_t bdd_node;

// This is internal
typedef struct bdd_node_entry {
    gen_event_filter_check* check;
    std::string check_str;
    bdd_node low;
    bdd_node high;
} bdd_node_entry_t;

class bdd_event_filter: public sinsp_filter
{
public:
    inline bdd_event_filter(): sinsp_filter(NULL) { }
    ~bdd_event_filter();

    bdd_node add_node(
            gen_event_filter_check* check,
            std::string& check_str,
            bdd_node low=s_bdd_false,
            bdd_node high=s_bdd_true);

    void set_entrypoint(bdd_node id);

    void optimize();

    bool run(gen_event *evt) override;

    std::set<uint16_t> evttypes() override;

    bool has_loop();

    inline uint32_t size()
    {
        return m_graph.size();
    }

    inline void print()
    {
        std::set<bdd_node> printed;
        printf("digraph{\n");
        printf("%d [label=true]\n", s_bdd_true);
        printf("%d [label=false]\n", s_bdd_false);
        for (bdd_node i = 0; i < m_graph.size(); i++)
        {
            if (printed.find(i) == printed.end())
            {
                printf("%d [label=\"%s\", shape=box]\n",
                    i, m_graph[i].check_str.c_str());
                printf("%d -> %d [style=dashed]\n%d -> %d\n",
                    i, m_graph[i].low,i, m_graph[i].high);
                printed.insert(i);
            }
        }
        printf("}\n");
    }

    static const bdd_node s_bdd_false = -1;
    static const bdd_node s_bdd_true = -2;

private:
    bool is_feasible(bdd_node node);
    bdd_node optimize(
        bdd_node root,
        std::vector<bdd_node_entry_t>& new_graph, 
        std::unordered_set<bdd_node>& pass,
        std::unordered_set<gen_event_filter_check*>& checks);

    bdd_node m_entrypoint = s_bdd_false;
    std::vector<bdd_node_entry_t> m_graph;
};

class bdd_event_filter_compiler: private libsinsp::filter::ast::expr_visitor
{
public:
    bdd_event_filter* compile(
        std::shared_ptr<gen_event_filter_factory> factory,
        libsinsp::filter::ast::expr* e,
        uint32_t check_id);

private:
    void visit(libsinsp::filter::ast::and_expr&) override;
    void visit(libsinsp::filter::ast::or_expr&) override;
    void visit(libsinsp::filter::ast::not_expr&) override;
    void visit(libsinsp::filter::ast::value_expr&) override;
    void visit(libsinsp::filter::ast::list_expr&) override;
    void visit(libsinsp::filter::ast::unary_check_expr&) override;
    void visit(libsinsp::filter::ast::binary_check_expr&) override;
    std::string create_filtercheck_name(std::string& name, std::string& arg);
    gen_event_filter_check* create_filtercheck(std::string& field);
    cmpop str_to_cmpop(std::string& str);

    bool m_expect_values;
    uint32_t m_check_id;
    bdd_node m_last_bdd_node;
    bdd_node m_low;
    bdd_node m_high;
    bdd_event_filter* m_cur_bdd;
    gen_event_filter_factory* m_factory;
    std::vector<std::string> m_field_values;
};