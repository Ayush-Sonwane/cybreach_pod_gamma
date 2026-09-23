# revalidation_service/src/service/delta_engine.py
"""Delta tracking, rule/version comparison, verdicts and improvement metrics
(Pod Gamma, Task 3)."""
from collections import Counter, defaultdict
from typing import Any, Dict, List

from src.core.config import get_settings
from src.core.contracts import (
    DeltaEntry,
    EventSnapshot,
    ImprovementReport,
    RevalidationRun,
    RuleRef,
    RuleVersionComparison,
)

EXCLUDED_DELTA_PATHS = ("metadata.provenance",)


def _diff_dicts(before: Dict[str, Any], after: Dict[str, Any], prefix: str = "") -> List[DeltaEntry]:
    deltas: List[DeltaEntry] = []
    keys = sorted(set(before.keys()) | set(after.keys()))

    for key in keys:
        path = f"{prefix}.{key}" if prefix else key
        old_value = before.get(key)
        new_value = after.get(key)

        if isinstance(old_value, dict) and isinstance(new_value, dict):
            deltas.extend(_diff_dicts(old_value, new_value, path))
            continue

        if isinstance(old_value, dict) or isinstance(new_value, dict):
            if old_value is None:
                change_type = "ADDED"
            elif new_value is None:
                change_type = "REMOVED"
            else:
                change_type = "CHANGED"
            deltas.append(
                DeltaEntry(ocsf_field=path, change_type=change_type,
                           old_value=old_value, new_value=new_value)
            )
            continue

        if old_value == new_value:
            if old_value is None:
                continue
            deltas.append(DeltaEntry(ocsf_field=path, change_type="UNCHANGED",
                                     old_value=old_value, new_value=new_value))
            continue

        if old_value is None:
            change_type = "ADDED"
        elif new_value is None:
            change_type = "REMOVED"
        else:
            change_type = "CHANGED"

        deltas.append(
            DeltaEntry(ocsf_field=path, change_type=change_type,
                       old_value=old_value, new_value=new_value)
        )
    return deltas


def diff_events(before_snapshot: EventSnapshot, after_snapshot: EventSnapshot) -> List[DeltaEntry]:
    """Field-level delta tracking between two snapshots (provenance noise excluded)."""
    deltas = _diff_dicts(before_snapshot.normalized, after_snapshot.normalized)
    return [d for d in deltas if not d.ocsf_field.startswith(EXCLUDED_DELTA_PATHS)]


def _rule_fields(rules: List[RuleRef]) -> Dict[str, RuleRef]:
    return {r.rule_id: r for r in rules}


def compare_rule_sets(
    before_snapshot: EventSnapshot, after_snapshot: EventSnapshot
) -> List[RuleVersionComparison]:
    """Rule/version comparison between two runs: which mappings changed version
    or were added/removed."""
    before = _rule_fields(before_snapshot.rules_used)
    after = _rule_fields(after_snapshot.rules_used)
    comparisons: List[RuleVersionComparison] = []

    for rule_id in sorted(set(before) | set(after)):
        old_rule = before.get(rule_id)
        new_rule = after.get(rule_id)
        comparisons.append(
            RuleVersionComparison(
                rule_id=rule_id,
                before_version=old_rule.version if old_rule else None,
                after_version=new_rule.version if new_rule else None,
                version_changed=bool(
                    old_rule and new_rule and old_rule.version != new_rule.version
                ),
                added_fields=[rule_id] if not old_rule and new_rule else [],
                removed_fields=[rule_id] if old_rule and not new_rule else [],
            )
        )

    for c in comparisons:
        if not c.added_fields and not c.removed_fields and c.before_version != c.after_version:
            c.version_changed = True
    return comparisons


def _responsible_rules(
    snapshot: EventSnapshot, deltas: List[DeltaEntry], positive: bool
) -> List[str]:
    rules = _rule_fields(snapshot.rules_used)
    responsible: List[str] = []
    for delta in deltas:
        if delta.ocsf_field.startswith("metadata."):
            continue
        if positive and delta.change_type not in ("ADDED", "CHANGED"):
            continue
        if not positive and delta.change_type not in ("REMOVED", "CHANGED"):
            continue
        prefix = f"map.{snapshot.vendor}."
        field = delta.ocsf_field
        rule = rules.get(f"{prefix}{field}")
        if rule is None:
            rule = next(
                (r for r in snapshot.rules_used
                 if r.rule_id.startswith(f"{prefix}{field}.")),
                None,
            )
        if rule is None:
            rule = rules.get(f"{prefix}base")
        if rule is not None and rule.rule_id not in responsible:
            responsible.append(rule.rule_id)
    return responsible


def evaluate(
    before: EventSnapshot,
    after: EventSnapshot,
    run_id: str,
    **run_extras,
) -> RevalidationRun:
    """Compare before/after snapshots and produce a verdict.

    Verdict rules:
      IMPROVED  -> confidence_delta >= improved_threshold
      DEGRADED  -> confidence_delta <= degraded_threshold
      UNCHANGED -> otherwise
    """
    settings = get_settings()
    deltas = diff_events(before, after)

    confidence_before = before.confidence.score
    confidence_after = after.confidence.score
    confidence_delta = round(confidence_after - confidence_before, 2)

    if confidence_delta >= settings.improved_threshold:
        verdict = "IMPROVED"
    elif confidence_delta <= settings.degraded_threshold:
        verdict = "DEGRADED"
    else:
        verdict = "UNCHANGED"

    return RevalidationRun(
        run_id=run_id,
        event_id=after.event_id,
        vendor=after.vendor,
        verdict=verdict,
        confidence_before=confidence_before,
        confidence_after=confidence_after,
        confidence_delta=confidence_delta,
        valid_before=before.verdict.is_valid,
        valid_after=after.verdict.is_valid,
        deltas=deltas,
        improved_by=_responsible_rules(after, deltas, positive=True),
        degraded_by=_responsible_rules(before, deltas, positive=False),
        before=before,
        after=after,
        **run_extras,
    )


def build_report(runs: List[RevalidationRun]) -> ImprovementReport:
    """Improvement metrics across all stored runs."""
    report = ImprovementReport(total_runs=len(runs))
    if not runs:
        return report

    counter = Counter(run.verdict for run in runs)
    report.improved_runs = counter["IMPROVED"]
    report.degraded_runs = counter["DEGRADED"]
    report.unchanged_runs = counter["UNCHANGED"]

    total_delta = sum(run.confidence_delta for run in runs)
    report.total_confidence_change = round(total_delta, 2)
    report.avg_confidence_delta = round(total_delta / len(runs), 2)

    rule_counts: Counter = Counter()
    rule_versions: Dict[str, str] = {}
    for run in runs:
        for rule_id in run.improved_by:
            rule_counts[rule_id] += 1
            for rule in run.after.rules_used:
                if rule.rule_id == rule_id:
                    rule_versions[rule_id] = rule.version

    report.top_rules_for_improvement = [
        {"rule_id": rule_id, "version": rule_versions.get(rule_id), "improvements": count}
        for rule_id, count in rule_counts.most_common(5)
    ]
    return report


def compare_rule_versions(
    runs: List[RevalidationRun], before_version: str, after_version: str
) -> List[RuleVersionComparison]:
    """History-based rule/version comparison: rule sets recorded at v1 vs v2."""
    grouped: Dict[str, Dict[str, set]] = defaultdict(lambda: defaultdict(set))
    for run in runs:
        for snapshot in (run.before, run.after):
            for rule in snapshot.rules_used:
                grouped[rule.rule_id][rule.version].add(run.run_id)

    comparisons: List[RuleVersionComparison] = []
    for rule_id in sorted(grouped):
        before_runs = grouped[rule_id].get(before_version, set())
        after_runs = grouped[rule_id].get(after_version, set())
        comparisons.append(
            RuleVersionComparison(
                rule_id=rule_id,
                before_version=before_version if before_runs else None,
                after_version=after_version if after_runs else None,
                version_changed=bool(after_runs and before_runs),
                added_fields=[rule_id] if not before_runs and after_runs else [],
                removed_fields=[rule_id] if before_runs and not after_runs else [],
            )
        )
    return comparisons