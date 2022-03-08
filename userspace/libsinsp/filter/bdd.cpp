#include "bdd.h"

using namespace std;

bdd_event_filter::~bdd_event_filter()
{
	std::unordered_set<gen_event_filter_check*> deleted;
    for (auto &node: m_graph)
    {
		if (deleted.find(node.check) == deleted.end())
		{
			deleted.insert(node.check);
			delete node.check;
		}
    }
}

bdd_node bdd_event_filter::add_node(
            gen_event_filter_check* check,
            std::string& check_str,
            bdd_node low,
            bdd_node high)
{
    m_graph.push_back({check, check_str, low, high});
    return m_graph.size() - 1;
}

void bdd_event_filter::set_entrypoint(bdd_node id)
{
    m_entrypoint = id;
}

bool bdd_event_filter::run(gen_event *evt)
{
    bdd_node cur = m_entrypoint;
    int32_t last_check_id = 0;
    while (cur >= 0)
    {
        last_check_id = m_graph[cur].check->get_check_id();
        cur = m_graph[cur].check->compare(evt)
            ? m_graph[cur].high
            : m_graph[cur].low;
    }
    if (cur == s_bdd_true)
    {
        evt->set_check_id(last_check_id);
        return true;
    }
    return false;
}

void bdd_event_filter::optimize()
{
	std::vector<bdd_node_entry_t> new_graph;
    std::unordered_set<bdd_node> pass;
	std::unordered_set<gen_event_filter_check*> checks;
    m_entrypoint = optimize(m_entrypoint, new_graph, pass, checks);
	for (auto &entry : m_graph)
	{
		if (checks.find(entry.check) == checks.end())
		{
			checks.insert(entry.check);
			delete entry.check;
		}
	}
    m_graph = new_graph;
    m_graph.shrink_to_fit();
	print();
}

bdd_node bdd_event_filter::optimize(
	bdd_node root,
	std::vector<bdd_node_entry_t>& new_graph, 
	std::unordered_set<bdd_node>& pass,
	std::unordered_set<gen_event_filter_check*>& checks)
{
	if (root >= 0 && pass.find(root) == pass.end())
    {
		auto new_node = new_graph.size();
		new_graph.push_back({
			m_graph[root].check,
			m_graph[root].check_str,
			s_bdd_false,
			s_bdd_true,
		});
		auto low = optimize(m_graph[root].low, new_graph, pass, checks);
		auto high = optimize(m_graph[root].high, new_graph, pass, checks);
		new_graph[new_node].low = low;
		new_graph[new_node].high = high;
		checks.insert(m_graph[root].check);
        pass.insert(new_node);
		root = new_node;
    }
    return root;
}

std::set<uint16_t> bdd_event_filter::evttypes()
{
    std::set<uint16_t> types;
    string prefix = "evt.type";
    for (auto &node : m_graph)
    {
        if (node.check_str.rfind(prefix) == 0 && is_feasible(node.high))
        {
            for (auto &t: node.check->evttypes())
            {
                types.insert(t);
            }
        }
    }
    return types;
}

bool bdd_event_filter::is_feasible(bdd_node node)
{
    if (node < 0)
    {
        return node == s_bdd_true;
    }
    return is_feasible(m_graph[node].low) || is_feasible(m_graph[node].high);
}

bdd_event_filter* bdd_event_filter_compiler::compile(
        std::shared_ptr<gen_event_filter_factory> factory,
        libsinsp::filter::ast::expr* e,
        uint32_t check_id)
{
    m_cur_bdd = new bdd_event_filter();
    m_last_bdd_node = bdd_event_filter::s_bdd_false;
    m_low = bdd_event_filter::s_bdd_false;
    m_high = bdd_event_filter::s_bdd_true;
    m_expect_values = false;
    m_check_id = check_id;
    m_factory = factory.get();
    e->accept(*this);
    m_cur_bdd->set_entrypoint(m_last_bdd_node);
    m_cur_bdd->optimize();
    return m_cur_bdd;
}


void bdd_event_filter_compiler::visit(libsinsp::filter::ast::and_expr& e)
{
    bdd_node cur_low = m_low;
    bdd_node cur_high = m_high;
    for (auto it = e.children.rbegin(); it != e.children.rend(); it++)
    {
        (*it)->accept(*this);
        m_high = m_last_bdd_node;
    }
    m_low = cur_low;
    m_high = cur_high;
}

void bdd_event_filter_compiler::visit(libsinsp::filter::ast::or_expr& e)
{
    bdd_node cur_low = m_low;
    bdd_node cur_high = m_high;
    for (auto it = e.children.rbegin(); it != e.children.rend(); it++)
    {
        (*it)->accept(*this);
        m_low = m_last_bdd_node;
    }
    m_low = cur_low;
    m_high = cur_high;
}

void bdd_event_filter_compiler::visit(libsinsp::filter::ast::not_expr& e)
{
    bdd_node cur_low = m_low;
    bdd_node cur_high = m_high;
    auto tmp = m_low;
    m_low = m_high;
    m_high = tmp;
    e.child->accept(*this);
    m_low = cur_low;
    m_high = cur_high;
}

void bdd_event_filter_compiler::visit(libsinsp::filter::ast::unary_check_expr& e)
{
    string field = create_filtercheck_name(e.field, e.arg);
	gen_event_filter_check *check = create_filtercheck(field);
	check->m_cmpop = str_to_cmpop(e.op);
	check->parse_field_name(field.c_str(), true, true);
	check->set_check_id(m_check_id);
    string check_str = field + " " + e.op;
    m_last_bdd_node = m_cur_bdd->add_node(check, check_str, m_low, m_high);
}

void bdd_event_filter_compiler::visit(libsinsp::filter::ast::binary_check_expr& e)
{
    string field = create_filtercheck_name(e.field, e.arg);
	gen_event_filter_check *check = create_filtercheck(field);
	check->m_cmpop = str_to_cmpop(e.op);
	check->parse_field_name(field.c_str(), true, true);
	check->set_check_id(m_check_id);

	// Read the the the right-hand values of the filtercheck. 
	// For list-related operators ('in', 'intersects', 'pmatch'), the vector
	// can be filled with more than 1 value, whereas in all other cases we
	// expect the vector to only have 1 value. We don't check this here, as
	// the parser is trusted to apply proper grammar checks on this constraint.
	m_expect_values = true;
	e.value->accept(*this);
	m_expect_values = false;
    string check_str = field + " " + e.op + " ";
    if (m_field_values.size() > 1)
    {
        check_str += "(";
    }
	for (size_t i = 0; i < m_field_values.size(); i++)
	{
        if (i > 0)
        {
            check_str += ", ";
        }
        check_str += m_field_values[i];
		check->add_filter_value(m_field_values[i].c_str(), m_field_values[i].size(), i);
	}
    if (m_field_values.size() > 1)
    {
        check_str += ")";
    }
    m_last_bdd_node = m_cur_bdd->add_node(check, check_str, m_low, m_high);
}

void bdd_event_filter_compiler::visit(libsinsp::filter::ast::value_expr& e)
{
    if (!m_expect_values)
	{
		throw sinsp_exception("filter error: unexpected identifier '" + e.value + "'");
	}
	m_field_values.clear();
	m_field_values.push_back(e.value);
}

void bdd_event_filter_compiler::visit(libsinsp::filter::ast::list_expr& e)
{
    if (!m_expect_values)
	{
		throw sinsp_exception("filter error: unexpected value list");
	}
	m_field_values.clear();
	m_field_values = e.values;
}

string bdd_event_filter_compiler::create_filtercheck_name(string& name, string& arg)
{
	// The filtercheck factories parse the name + arg as a whole.
	// We keep this for now, but we may want to change this in the future.
	// todo(jasondellaluce): handle field arg parsing at compilation time
	string fld = name;
	if (arg.size() > 0)
	{
		fld += "[" + arg + "]";
	}
	return fld;
}

gen_event_filter_check* bdd_event_filter_compiler::create_filtercheck(string& field)
{
	gen_event_filter_check *chk = m_factory->new_filtercheck(field.c_str());
	if(chk == NULL)
	{
		throw sinsp_exception("filter_check called with nonexistent field " + field);
	}
	return chk;
}

cmpop bdd_event_filter_compiler::str_to_cmpop(string& str)
{
	if(str == "=" || str == "==")
	{
		return CO_EQ;
	}
	else if(str == "!=")
	{
		return CO_NE;
	}
	else if(str == "<=")
	{
		return CO_LE;
	}
	else if(str == "<")
	{
		return CO_LT;
	}
	else if(str == ">=")
	{
		return CO_GE;
	}
	else if(str == ">")
	{
		return CO_GT;
	}
	else if(str == "contains")
	{
		return CO_CONTAINS;
	}
	else if(str == "icontains")
	{
		return CO_ICONTAINS;
	}
	else if(str == "startswith")
	{
		return CO_STARTSWITH;
	}
	else if(str == "endswith")
	{
		return CO_ENDSWITH;
	}
	else if(str == "in")
	{
		return CO_IN;
	}
	else if(str == "intersects")
	{
		return CO_INTERSECTS;
	}
	else if(str == "pmatch")
	{
		return CO_PMATCH;
	}
	else if(str == "exists")
	{
		return CO_EXISTS;
	}
	else if(str == "glob")
	{
		return CO_GLOB;
	}
	// we are not supposed to get here, as the parser pre-checks this
	ASSERT(false);
	throw sinsp_exception("filter error: unrecognized comparison operator '" + string(str) + "'");
}
