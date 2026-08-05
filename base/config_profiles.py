from __future__ import annotations

import json
import re
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from base.config import _PROJECT_ROOT


CONFIG_PROFILES_PATH = _PROJECT_ROOT / ".spore_config_profiles.json"

MAIN_SDK_PROFILE_KEYS: Dict[str, List[str]] = {
    "openai": [
        "OPENAI_API_KEY",
        "OPENAI_API_URL",
        "OPENAI_MODEL",
        "USE_RESPONSES_API",
        "OPENAI_REASONING_EFFORT",
    ],
    "anthropic": [
        "ANTHROPIC_API_KEY",
        "ANTHROPIC_API_URL",
        "ANTHROPIC_MODEL",
        "ANTHROPIC_EFFORT",
        "ANTHROPIC_THINKING_MODE",
        "ANTHROPIC_THINKING_BUDGET_TOKENS",
    ],
}

SUB_AGENT_SDK_PROFILE_KEYS: Dict[str, List[str]] = {
    "openai": [
        "SUB_AGENT_OPENAI_API_KEY",
        "SUB_AGENT_OPENAI_API_URL",
        "SUB_AGENT_OPENAI_MODEL",
    ],
    "anthropic": [
        "SUB_AGENT_ANTHROPIC_API_KEY",
        "SUB_AGENT_ANTHROPIC_API_URL",
        "SUB_AGENT_ANTHROPIC_MODEL",
    ],
}

COMMON_PROFILE_KEYS: List[str] = [
    "LLM_STREAM_ENABLED",
    "CLEAN_SDK_HEADERS",
    "SYSTEM_AS_USER",
    "SYSTEM_PROMPT_FILE",
    "MAX_OUTPUT_TOKENS",
    "CONTEXT_MAX_TOKENS",
    "CONTEXT_WARNING_THRESHOLD",
    "MAX_SINGLE_MESSAGE_RATIO",
    "API_TIMEOUT",
]

ANTHROPIC_COMPAT_PROFILE_KEYS: List[str] = [
    "CLEAN_AUTH_HEADER",
]

# Superset used for validation and .env insertion order.
PROFILE_ENV_KEYS: List[str] = [
    "LLM_SDK",
    "OPENAI_API_KEY",
    "OPENAI_API_URL",
    "OPENAI_MODEL",
    "USE_RESPONSES_API",
    "OPENAI_REASONING_EFFORT",
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_API_URL",
    "ANTHROPIC_MODEL",
    "ANTHROPIC_EFFORT",
    "ANTHROPIC_THINKING_MODE",
    "ANTHROPIC_THINKING_BUDGET_TOKENS",
    "SUB_AGENT_LLM_SDK",
    "SUB_AGENT_OPENAI_API_KEY",
    "SUB_AGENT_OPENAI_API_URL",
    "SUB_AGENT_OPENAI_MODEL",
    # SUB_AGENT advanced params (were missing — caused silent drop on save/apply)
    "SUB_AGENT_USE_RESPONSES_API",
    "SUB_AGENT_OPENAI_REASONING_EFFORT",
    "SUB_AGENT_ANTHROPIC_API_KEY",
    "SUB_AGENT_ANTHROPIC_API_URL",
    "SUB_AGENT_ANTHROPIC_MODEL",
    "SUB_AGENT_ANTHROPIC_EFFORT",
    "SUB_AGENT_ANTHROPIC_THINKING_MODE",
    "SUB_AGENT_ANTHROPIC_THINKING_BUDGET_TOKENS",
    "SUB_AGENT_MAX_OUTPUT_TOKENS",
    "LLM_STREAM_ENABLED",
    "CLEAN_SDK_HEADERS",
    "CLEAN_AUTH_HEADER",
    "SYSTEM_AS_USER",
    "SYSTEM_PROMPT_FILE",
    "MAX_OUTPUT_TOKENS",
    "CONTEXT_MAX_TOKENS",
    "CONTEXT_WARNING_THRESHOLD",
    "MAX_SINGLE_MESSAGE_RATIO",
    "API_TIMEOUT",
]

# Granular per-agent base keys (AGENT_SUPERVISOR/MODE_SELECTOR/SECURITY/FRONTEND).
# Generated to stay in sync with the frontend AGENT_BASE_PROFILE_KEYS constant.
# All were missing from PROFILE_ENV_KEYS, causing silent drop on profile save/apply.
_AGENT_BASE_PREFIXES = [
    "AGENT_SUPERVISOR",
    "AGENT_MODE_SELECTOR",
    "AGENT_SECURITY",
    "AGENT_FRONTEND",
]
_AGENT_BASE_SUFFIXES = [
    "LLM_SDK",
    "OPENAI_API_KEY", "OPENAI_API_URL", "OPENAI_MODEL",
    "USE_RESPONSES_API", "OPENAI_REASONING_EFFORT",
    "ANTHROPIC_API_KEY", "ANTHROPIC_API_URL", "ANTHROPIC_MODEL",
    "ANTHROPIC_EFFORT", "ANTHROPIC_THINKING_MODE", "ANTHROPIC_THINKING_BUDGET_TOKENS",
    "MAX_OUTPUT_TOKENS",
]
PROFILE_ENV_KEYS = PROFILE_ENV_KEYS + [
    f"{p}_{s}" for p in _AGENT_BASE_PREFIXES for s in _AGENT_BASE_SUFFIXES
]

VALID_SDKS = set(MAIN_SDK_PROFILE_KEYS.keys())


def _empty_store() -> Dict[str, Any]:
    return {
        "version": 1,
        "active_profile_id": None,
        "profiles": [],
    }


def _load_store() -> Dict[str, Any]:
    if not CONFIG_PROFILES_PATH.exists():
        return _empty_store()

    with CONFIG_PROFILES_PATH.open("r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, dict):
        return _empty_store()

    profiles = data.get("profiles")
    if not isinstance(profiles, list):
        profiles = []

    normalized_profiles = []
    for profile in profiles:
        if not isinstance(profile, dict):
            continue
        profile_id = str(profile.get("id") or "").strip()
        name = str(profile.get("name") or "").strip()
        values = _normalize_values(profile.get("values") or {})
        if not profile_id or not name or not values:
            continue
        normalized_profiles.append(
            {
                "id": profile_id,
                "name": name,
                "description": str(profile.get("description") or ""),
                "values": values,
                "created_at": float(profile.get("created_at") or 0),
                "updated_at": float(profile.get("updated_at") or 0),
            }
        )

    active_profile_id = data.get("active_profile_id")
    if active_profile_id is not None:
        active_profile_id = str(active_profile_id)

    return {
        "version": 1,
        "active_profile_id": active_profile_id,
        "profiles": normalized_profiles,
    }


def _save_store(store: Dict[str, Any]) -> None:
    CONFIG_PROFILES_PATH.write_text(
        json.dumps(store, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def _normalize_values(values: Dict[str, Any]) -> Dict[str, str]:
    raw_values: Dict[str, str] = {}
    if not isinstance(values, dict):
        return raw_values

    allowed_keys = set(PROFILE_ENV_KEYS)
    for key, value in values.items():
        key = str(key).strip()
        if key not in allowed_keys:
            continue
        normalized_value = str(value).replace("\r", " ").replace("\n", " ").strip()
        if not normalized_value:
            continue
        raw_values[key] = normalized_value

    normalized: Dict[str, str] = {}

    main_sdk = raw_values.get("LLM_SDK", "").lower()
    if main_sdk not in VALID_SDKS:
        main_sdk = _infer_sdk(raw_values, MAIN_SDK_PROFILE_KEYS)
    if main_sdk in VALID_SDKS:
        normalized["LLM_SDK"] = main_sdk
        for key in MAIN_SDK_PROFILE_KEYS[main_sdk]:
            if key in raw_values:
                normalized[key] = raw_values[key]

    sub_agent_sdk = raw_values.get("SUB_AGENT_LLM_SDK", "").lower()
    if sub_agent_sdk in VALID_SDKS:
        normalized["SUB_AGENT_LLM_SDK"] = sub_agent_sdk
        for key in SUB_AGENT_SDK_PROFILE_KEYS[sub_agent_sdk]:
            if key in raw_values:
                normalized[key] = raw_values[key]

    for key in COMMON_PROFILE_KEYS:
        if key in raw_values:
            normalized[key] = raw_values[key]

    if (
        (main_sdk == "anthropic" or sub_agent_sdk == "anthropic")
        and "CLEAN_AUTH_HEADER" in raw_values
    ):
        normalized["CLEAN_AUTH_HEADER"] = raw_values["CLEAN_AUTH_HEADER"]

    # Granular per-agent base keys — copy all that survived the whitelist filter.
    for key in PROFILE_ENV_KEYS:
        if key.startswith(tuple(p + "_" for p in _AGENT_BASE_PREFIXES)):
            if key in raw_values and key not in normalized:
                normalized[key] = raw_values[key]

    return normalized


def _infer_sdk(values: Dict[str, str], key_groups: Dict[str, List[str]]) -> str:
    matched_sdks = [
        sdk
        for sdk, keys in key_groups.items()
        if any(key in values for key in keys)
    ]
    return matched_sdks[0] if len(matched_sdks) == 1 else ""


def _slugify(value: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9_-]+", "-", value.strip().lower()).strip("-")
    return slug or f"profile-{uuid.uuid4().hex[:8]}"


def _unique_profile_id(name: str, profiles: List[Dict[str, Any]]) -> str:
    existing_ids = {str(profile.get("id")) for profile in profiles}
    base_id = _slugify(name)
    profile_id = base_id
    index = 2
    while profile_id in existing_ids:
        profile_id = f"{base_id}-{index}"
        index += 1
    return profile_id


def read_env_values(env_path: Path) -> Dict[str, str]:
    values: Dict[str, str] = {}
    if not env_path.exists():
        return values

    for line in env_path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        values[key.strip()] = value.strip()

    return values


def write_env_values(env_path: Path, updates: Dict[str, str]) -> None:
    if not env_path.exists():
        raise FileNotFoundError(".env file does not exist")

    filtered_updates = _normalize_values(updates)
    if not filtered_updates:
        return

    original_lines = env_path.read_text(encoding="utf-8").splitlines(keepends=True)
    updated_keys = set()
    new_lines: List[str] = []

    for line in original_lines:
        content = line.rstrip("\r\n")
        newline = line[len(content):] or "\n"
        stripped = content.strip()

        if stripped and not stripped.startswith("#") and "=" in stripped:
            key = stripped.split("=", 1)[0].strip()
            if key in filtered_updates:
                new_lines.append(f"{key}={filtered_updates[key]}{newline}")
                updated_keys.add(key)
                continue

        new_lines.append(line)

    missing_keys = [key for key in PROFILE_ENV_KEYS if key in filtered_updates and key not in updated_keys]
    if missing_keys:
        if new_lines and not new_lines[-1].endswith(("\n", "\r")):
            new_lines[-1] = f"{new_lines[-1]}\n"
        if new_lines and new_lines[-1].strip():
            new_lines.append("\n")
        new_lines.append("# Config profile overrides\n")
        for key in missing_keys:
            new_lines.append(f"{key}={filtered_updates[key]}\n")

    env_path.write_text("".join(new_lines), encoding="utf-8")


def _profile_matches_env(profile: Dict[str, Any], env_values: Dict[str, str]) -> bool:
    values = profile.get("values") or {}
    if not values:
        return False
    return all(env_values.get(key, "") == str(value) for key, value in values.items())


def _detect_active_profile(store: Dict[str, Any], env_path: Path) -> Optional[str]:
    env_values = read_env_values(env_path)
    profiles = store.get("profiles") or []

    stored_active = store.get("active_profile_id")
    if stored_active:
        active_profile = next((profile for profile in profiles if profile.get("id") == stored_active), None)
        if active_profile and _profile_matches_env(active_profile, env_values):
            return str(stored_active)

    for profile in profiles:
        if _profile_matches_env(profile, env_values):
            return str(profile.get("id"))

    return None


def list_config_profiles(env_path: Path) -> Dict[str, Any]:
    store = _load_store()
    active_profile_id = _detect_active_profile(store, env_path)
    if store.get("active_profile_id") != active_profile_id:
        store["active_profile_id"] = active_profile_id
        _save_store(store)

    profiles = []
    for profile in store.get("profiles") or []:
        values = dict(profile.get("values") or {})
        profiles.append(
            {
                "id": profile["id"],
                "name": profile["name"],
                "description": profile.get("description", ""),
                "values": values,
                "keys": list(values.keys()),
                "is_active": profile["id"] == active_profile_id,
                "created_at": profile.get("created_at", 0),
                "updated_at": profile.get("updated_at", 0),
            }
        )

    return {
        "success": True,
        "profiles": profiles,
        "active_profile_id": active_profile_id,
        "storage_path": str(CONFIG_PROFILES_PATH),
        "env_keys": PROFILE_ENV_KEYS,
    }


def save_config_profile(
    name: str,
    values: Dict[str, Any],
    profile_id: Optional[str] = None,
    description: str = "",
) -> Dict[str, Any]:
    name = name.strip()
    if not name:
        raise ValueError("Profile name is required")

    normalized_values = _normalize_values(values)
    if not normalized_values:
        raise ValueError("Profile must contain at least one switchable config value")

    store = _load_store()
    profiles = store["profiles"]
    now = time.time()

    existing_profile = None
    if profile_id:
        existing_profile = next((profile for profile in profiles if profile.get("id") == profile_id), None)

    if existing_profile:
        existing_profile["name"] = name
        existing_profile["description"] = description
        existing_profile["values"] = normalized_values
        existing_profile["updated_at"] = now
        profile = existing_profile
    else:
        profile = {
            "id": _unique_profile_id(name, profiles),
            "name": name,
            "description": description,
            "values": normalized_values,
            "created_at": now,
            "updated_at": now,
        }
        profiles.append(profile)

    _save_store(store)
    return {"success": True, "profile": profile}


def delete_config_profile(profile_id: str) -> Dict[str, Any]:
    store = _load_store()
    profiles = store["profiles"]
    remaining_profiles = [profile for profile in profiles if profile.get("id") != profile_id]

    if len(remaining_profiles) == len(profiles):
        raise ValueError("Profile does not exist")

    store["profiles"] = remaining_profiles
    if store.get("active_profile_id") == profile_id:
        store["active_profile_id"] = None

    _save_store(store)
    return {"success": True}


def apply_config_profile(profile_id: str, env_path: Path) -> Dict[str, Any]:
    store = _load_store()
    profile = next((item for item in store["profiles"] if item.get("id") == profile_id), None)
    if not profile:
        raise ValueError("Profile does not exist")

    values = _normalize_values(profile.get("values") or {})
    if not values:
        raise ValueError("Profile does not contain applicable config values")

    write_env_values(env_path, values)
    store["active_profile_id"] = profile_id
    _save_store(store)

    return {
        "success": True,
        "profile": profile,
        "env_values": read_env_values(env_path),
    }
