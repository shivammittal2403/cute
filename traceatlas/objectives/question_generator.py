"""traceatlas.objectives.question_generator - Sub-questions from an objective."""
from __future__ import annotations

from traceatlas.core.objective_spec import ObjectiveSpec

_TEMPLATES = {
    "domainint": ["What is the registration history of {v}?",
                  "Which IPs does {v} resolve to (current and historical)?",
                  "Who else is hosted on the same infrastructure?"],
    "corpint": ["What is the registered legal identity of {v}?",
                "Who are its officers/owners?", "What subsidiaries exist?"],
    "personint": ["What public identities are associated with {v}?",
                  "Which organisations is {v} affiliated with?"],
    "usernameint": ["On which platforms does handle {v} exist?",
                    "Do the profiles correlate to one person?"],
    "infraint": ["What ASN/hosting owns {v}?", "What other services share it?"],
    "cti": ["What actor/campaign is {v} associated with?",
            "Which CVEs are involved?"],
    "webint": ["What authoritative pages mention {v}?"],
}


def generate_questions(spec: ObjectiveSpec, discipline: str) -> list[str]:
    qs: list[str] = []
    for t in spec.targets[:5]:
        for tmpl in _TEMPLATES.get(discipline, _TEMPLATES["webint"]):
            qs.append(tmpl.format(v=t.value or t.kind.value))
    return qs
