from base.html_semantic_intent import (
    ALLOWED_EVENT_TYPES,
    DYNAMIC_WINDOW_POLICY,
    normalize_candidate_event,
    normalize_semantic_intent_snapshot,
)


def test_candidate_event_is_bounded_redacted_and_marked_untrusted():
    event = normalize_candidate_event({
        "event_type": "unsupported-provider-command",
        "text": "password=hunter2",
        "selection_text": "access_token=abc123",
        "ancestors": ["a", "b", "c", "d", "e"],
        "control": {"type": "password", "value": "very-secret"},
        "semantic_context": {
            "object_name": "PointerToRawData",
            "object_type": "field",
            "domain": "PE/COFF",
            "semantic_path": "IMAGE_SECTION_HEADER > PointerToRawData",
            "container_ref": "section-table",
            "current_value": "api_key=secret-value",
            "instance_data": "offset=0x400",
            "related_refs": [f"field-{index}" for index in range(10)],
            "explanation_present": False,
            "inspector_ref": "pe-inspector",
        },
        "local_outcome": {
            "observed": True,
            "changed": False,
            "satisfied": False,
            "before_signature": "before",
            "after_signature": "after",
        },
    })

    assert event["event_type"] == "click"
    assert event["trust_level"] == "iframe_bridge_candidate"
    assert "hunter2" not in event["text"]
    assert "abc123" not in event["selection_text"]
    assert event["control"] == {
        "type": "password", "value": "[REDACTED]", "checked": False, "redacted": True,
    }
    assert event["ancestors"] == ["a", "b", "c", "d"]
    assert event["semantic_context"]["object_name"] == "PointerToRawData"
    assert event["semantic_context"]["current_value"] == "[REDACTED]"
    assert len(event["semantic_context"]["related_refs"]) == 6
    assert event["local_outcome"]["observed"] is True
    assert event["local_outcome"]["satisfied"] is False


def test_semantic_snapshot_compresses_evidence_refs_and_domain_responsibility():
    evidence = [
        {
            "event_type": "dblclick",
            "elapsed_ms": index * 100,
            "focus_ref": f"PE.Field{index}",
            "word": f"Field{index}",
            "local_outcome": {"observed": True, "changed": False, "satisfied": False},
        }
        for index in range(20)
    ]
    snapshot = normalize_semantic_intent_snapshot({
        "episode_id": "episode-1",
        "intent_epoch": 9,
        "started_at_ms": 100,
        "ended_at_ms": 800,
        "semantic_focus_ref": "PE.PointerToRawData",
        "presentation_target_ref": "pe-inspector",
        "mutation_target_ref": "body > main",
        "focus": {
            "label": "PointerToRawData",
            "context": ["PE", "IMAGE_SECTION_HEADER", "row", "value", "ignored"],
            "selected_text": "PointerToRawData",
            "object_type": "field",
            "domain": "PE/COFF",
            "semantic_path": "IMAGE_SECTION_HEADER > PointerToRawData",
            "current_value": "0x00000400",
            "instance_data": "raw file offset",
            "explanation_present": False,
            "inspector_ref": "pe-inspector",
        },
        "evidence": evidence,
        "candidate_intents": [
            "explain_semantic_object",
            "compare_semantic_objects",
            "understand_value",
            "open_existing_inspector",
            "ignored_fifth",
        ],
        "confidence": "high",
        "local_outcome": "not_satisfied",
    })

    assert snapshot is not None
    assert len(snapshot["evidence"]) == 12
    assert len(snapshot["candidate_intents"]) == 4
    assert snapshot["semantic_focus_ref"] == "PE.PointerToRawData"
    assert snapshot["presentation_target_ref"] == "pe-inspector"
    assert snapshot["mutation_target_ref"] == "body > main"
    assert snapshot["focus"]["current_value"] == "0x00000400"
    assert snapshot["local_outcome"] == "not_satisfied"
    assert snapshot["trust_level"] == "iframe_bridge_candidate"
    assert snapshot["knowledge_requirement"] == {
        "required": True,
        "content_owner": "main_or_specialist_agent",
        "frontend_agent_role": "intent_resolution_and_page_expression",
        "reasons": ["candidate_intent", "page_content_gap"],
    }
    assert snapshot["window_policy"] == DYNAMIC_WINDOW_POLICY


def test_dynamic_window_policy_has_no_fixed_five_second_batch():
    assert DYNAMIC_WINDOW_POLICY["maximum_lifetime"]["max_ms"] < 5000
    assert {
        "immediate",
        "short_stable",
        "input_silence",
        "ambiguous_selection",
        "local_outcome_observation",
        "maximum_lifetime",
    } <= set(DYNAMIC_WINDOW_POLICY)
    assert all(5000 not in policy.values() for policy in DYNAMIC_WINDOW_POLICY.values())


def test_selection_clear_is_allowed_but_not_forwarded_as_agent_evidence():
    cancellation = normalize_candidate_event({"event_type": "selection_clear"})
    assert "selection_clear" in ALLOWED_EVENT_TYPES
    assert cancellation["event_type"] == "selection_clear"

    snapshot = normalize_semantic_intent_snapshot({
        "evidence": [
            {
                "event_type": "selection_clear",
                "elapsed_ms": 10,
                "focus_ref": "cleared-field",
                "semantic_context": {"object_name": "Cancelled selection"},
            },
            {
                "event_type": "dblclick",
                "elapsed_ms": 20,
                "focus_ref": "PE.PointerToRawData",
                "semantic_context": {
                    "object_name": "PointerToRawData",
                    "object_type": "field",
                    "domain": "PE/COFF",
                    "semantic_path": "IMAGE_SECTION_HEADER > PointerToRawData",
                    "current_value": "password=do-not-forward",
                    "instance_data": "x" * 700,
                    "container_ref": "section-table",
                    "inspector_ref": "pe-inspector",
                    "related_refs": [f"related-{index}" for index in range(9)],
                    "explanation_present": False,
                    "arbitrary_nested": {"must": "be dropped"},
                },
            },
        ],
    })

    assert snapshot is not None
    assert [item["event_type"] for item in snapshot["evidence"]] == ["dblclick"]
    context = snapshot["evidence"][0]["semantic_context"]
    assert context["object_name"] == "PointerToRawData"
    assert context["current_value"] == "[REDACTED]"
    assert len(context["instance_data"]) == 500
    assert len(context["related_refs"]) == 6
    assert "arbitrary_nested" not in context


def test_semantic_snapshot_keeps_at_most_four_bounded_focuses():
    focuses = [
        {
            "ref": f"PE.Field{index}",
            "label": f"Field {index}",
            "object_type": "field",
            "domain": "PE/COFF",
            "semantic_path": f"IMAGE_SECTION_HEADER > Field{index}",
            "current_value": f"api_key=secret-{index}",
            "instance_data": "offset=" + ("9" * 600),
            "explanation_present": index % 2 == 0,
            "inspector_ref": "pe-inspector",
            "container_ref": "section-table",
            "related_refs": [f"field-{item}" for item in range(10)],
            "untrusted_extra": "drop me",
        }
        for index in range(6)
    ]
    snapshot = normalize_semantic_intent_snapshot({
        "semantic_focus_ref": "PE.Field0",
        "focuses": focuses,
    })

    assert snapshot is not None
    assert len(snapshot["focuses"]) == 4
    first = snapshot["focuses"][0]
    assert set(first) == {
        "ref", "label", "object_type", "domain", "semantic_path", "current_value",
        "instance_data", "explanation_present", "inspector_ref", "container_ref",
        "related_refs",
    }
    assert first["ref"] == "PE.Field0"
    assert first["current_value"] == "[REDACTED]"
    assert len(first["instance_data"]) == 500
    assert len(first["related_refs"]) == 6
    assert snapshot["focus"]["ref"] == "PE.Field0"


def test_privacy_strips_url_query_fragment_and_redacts_default_control_values():
    event = normalize_candidate_event({
        "href": "https://example.test/docs/field?token=secret#section",
        "control": {"type": "text", "value": "ordinary-default"},
    })

    assert event["href"] == "https://example.test/docs/field"
    assert event["control"] == {
        "type": "text", "value": "[REDACTED]", "checked": False, "redacted": True,
    }


def test_explicit_explain_compare_and_page_gap_require_knowledge_without_candidate_prefix():
    explicit = normalize_semantic_intent_snapshot({
        "explicit_request": "Please compare these fields and explain the difference",
        "focus": {"label": "FieldA", "explanation_present": True},
        "candidate_intents": ["inspect_field"],
    })
    gap = normalize_semantic_intent_snapshot({
        "focus": {
            "label": "PointerToRawData",
            "object_type": "field",
            "domain": "PE/COFF",
            "current_value": "0x400",
            "explanation_present": False,
        },
        "evidence": [{"event_type": "dblclick", "word": "PointerToRawData"}],
        "candidate_intents": ["inspect_field"],
        "local_outcome": "not_satisfied",
    })

    assert explicit["knowledge_requirement"]["required"] is True
    assert "explicit_explain_or_compare_request" in explicit["knowledge_requirement"]["reasons"]
    assert gap["knowledge_requirement"]["required"] is True
    assert "page_content_gap" in gap["knowledge_requirement"]["reasons"]
