"""
The trusted context the AI triage sees: records from the SOC's own files.

An alert's text is written by whoever caused it, often an attacker. These
records are not: they come from soc_context.yml, which only the SOC edits.
ai-alert-triage's strict mode dismisses an alert only when the model cites
one of them, so an attacker can't talk the model into a dismissal with a
claim like "approved by the security team" inside the alert itself.
"""

import ipaddress
from functools import lru_cache
from pathlib import Path

import yaml

from app.config import get_settings


@lru_cache
def _load(path: str) -> dict:
    file = Path(path)
    if not file.exists():
        return {}
    data = yaml.safe_load(file.read_text(encoding="utf-8")) or {}
    return data if isinstance(data, dict) else {}


def load() -> dict:
    return _load(get_settings().SOC_CONTEXT_FILE)


def _ips(incident) -> list[str]:
    found = []
    for alert in incident.alerts:
        raw = alert.raw_data or {}
        for key in ("src_ip", "source_ip", "ip"):
            if raw.get(key):
                found.append(str(raw[key]))
    found += [ioc.value for ioc in incident.iocs if getattr(ioc.type, "value", ioc.type) == "ip"]
    unique = []
    for ip in found:
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            continue
        if ip not in unique:
            unique.append(ip)
    return unique


def _domains(incident) -> list[str]:
    found = []
    for alert in incident.alerts:
        sender = str((alert.raw_data or {}).get("from") or "")
        if "@" in sender:
            found.append(sender.rsplit("@", 1)[1].strip(" >\"'").lower())
    return list(dict.fromkeys(found))


def context_for(incident) -> dict:
    """The trusted records that match this incident's IP addresses and sender domains."""
    data = load()
    context = {}
    if data.get("org_domain"):
        context["org_domain"] = data["org_domain"]
    matches = [(ip, (data.get("by_ip") or {}).get(ip)) for ip in _ips(incident)] + \
              [(d, (data.get("by_domain") or {}).get(d)) for d in _domains(incident)]
    for key, records in matches:
        if not isinstance(records, dict):
            continue
        for name, record in records.items():
            if name in context:          # the first match wins; one record per kind is enough
                continue
            context[name] = {"matches": key, **record} if isinstance(record, dict) else f"{record} (matches {key})"
    return context
