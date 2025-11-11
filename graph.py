from langgraph.graph import StateGraph, END
from nodes.evidence import plan_evidence, load_logs, analyze_evidence
from nodes.policy import build_policy_indexes, select_policies, read_policies
from nodes.gap_analysis import compare_policies, validate_vs_evidence, finalize_report

def build_graph():
    g = StateGraph(dict)

    # Register nodes
    g.add_node("plan_evidence", plan_evidence)
    g.add_node("load_logs", load_logs)
    g.add_node("analyze_evidence", analyze_evidence)

    g.add_node("build_policy_indexes", build_policy_indexes)
    g.add_node("select_policies", select_policies)
    g.add_node("read_policies", read_policies)

    g.add_node("compare_policies", compare_policies)
    g.add_node("validate_vs_evidence", validate_vs_evidence)
    g.add_node("finalize_report", finalize_report)

    g.set_entry_point("plan_evidence")

    g.add_edge("plan_evidence", "load_logs")
    g.add_edge("load_logs", "analyze_evidence")

    g.add_edge("analyze_evidence", "build_policy_indexes")
    g.add_edge("build_policy_indexes", "select_policies")
    g.add_edge("select_policies", "read_policies")

    g.add_edge("read_policies", "compare_policies")
    g.add_edge("compare_policies", "validate_vs_evidence")
    g.add_edge("validate_vs_evidence", "finalize_report")
    g.add_edge("finalize_report", END)

    return g.compile()
