"""只表达当前审计证据支持的边界，不制造匹配或标签。"""


def assess_alignment() -> dict:
    """当前 March-01 CSV 与本版基础 flow 的直接可信 join 不可建立。"""
    return {"status": "unmatchable", "scope": "direct_trusted_join_to_audited_March01_CSV",
            "candidate_status": "unverified", "label": None,
            "compatible_with_78_features": False,
            "reasons": ["CSV lacks source/destination IP, source port and reliable flow ID",
                        "CSV clock semantics and CICFlowMeter V3 parameters unverified",
                        "No real PCAP imported in this milestone; no record mapping supplied",
                        "NetSentry basic metadata is not the CICFlowMeter 78-feature contract"],
            "next_evidence": ["trusted packet-to-flow mapping and extractor configuration",
                              "verified clock conversion and flow-level annotation provenance"]}
