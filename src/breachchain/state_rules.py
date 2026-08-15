"""Hand-curated requires/provides tags for a subset of the ART candidate pool,
keyed by (technique_id, guid).

ART's own YAML carries no such metadata (art_loader.AtomicTest has no
requires/provides fields), so this is the missing piece the state-driven
orchestrator (art_runner.run_state_driven) needs to decide "can this run
given what we've found so far" and "what did running it actually get us".

Honest scope note: the safety-filtered candidate pool (art_safe_candidates.json)
only contains standalone, single-target ART tests -- it has no T1078/T1021
"validate found creds against a new host" style candidates (those need
elevation or a second target, both excluded by the safety filter). So today
almost nothing in the pool genuinely *requires* something; the meaningful
half of this file is `PROVIDES` -- getting state.py to actually fill in from
real command output instead of staying decorative. `REQUIRES` is here,
correct, and wired end-to-end, but has few real entries until multi-target
lateral movement exists (see README 7-1/7-2).

Untagged (technique_id, guid) pairs default to no requirements (always
eligible) and no provides (their success doesn't feed state) -- tagging is
additive, not a whitelist, so the rest of the 233-candidate pool keeps
running exactly as before.
"""
from __future__ import annotations

import re

# requires: list of predicate strings, ALL must hold against current ScenarioState
#   "credential"      -> at least one credential has been found so far
#   "access:<level>"  -> an AccessGrant with this level exists for the current target
# provides: list of effect strings, applied to state after a successful run
#   "credential"      -> stdout is scanned with _CREDENTIAL_PATTERNS and any
#                        matches are recorded as Credential entries
REQUIRES: dict[tuple[str, str], list[str]] = {
    # Nothing in the current safety-filtered pool has a real prerequisite --
    # see the module docstring. Left explicit (not empty dict) as the place
    # future multi-target candidates get tagged, e.g.:
    #   ("T1021.004", "<guid>"): ["credential"],
}

PROVIDES: dict[tuple[str, str], list[str]] = {
    # Only candidates whose command prints the finding to stdout (not a file)
    # are tagged -- see art_runner.py's state-driven runner for why.
    ("T1552.001", "bd4cf0d1-7646-474e-8610-78ccf5a097c4"): ["credential"],  # grep -ri password #{file_path}
    ("T1552.001", "da4f751a-020b-40d7-b9ff-d433b7799803"): ["credential"],  # find/cat .netrc
}

# Heuristic patterns for pulling a plausible secret out of matched stdout.
# Deliberately loose (this is recon-quality extraction, not validation) --
# every hit gets recorded as a Credential candidate for a human/next-step to
# actually try, not a verified working credential.
_CREDENTIAL_PATTERNS = [
    re.compile(r"password\s*[:=]\s*(\S+)", re.IGNORECASE),
    re.compile(r"passwd\s*[:=]\s*(\S+)", re.IGNORECASE),
    re.compile(r"machine\s+\S+\s+login\s+(\S+)\s+password\s+(\S+)", re.IGNORECASE),  # .netrc
]


def extract_credentials(stdout: str) -> list[str]:
    found: list[str] = []
    for line in stdout.splitlines():
        for pattern in _CREDENTIAL_PATTERNS:
            m = pattern.search(line)
            if m:
                found.extend(g for g in m.groups() if g)
    return found


def requires_for(technique_id: str, guid: str) -> list[str]:
    return REQUIRES.get((technique_id, guid), [])


def provides_for(technique_id: str, guid: str) -> list[str]:
    return PROVIDES.get((technique_id, guid), [])
