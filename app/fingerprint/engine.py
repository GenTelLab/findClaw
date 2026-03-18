import logging
from collections import defaultdict

from app.fingerprint.exclusion_filter import ExclusionFilter
from app.fingerprint.loader import FingerprintLoader
from app.fingerprint.rule import FingerprintRule, MatchResult
from app.scanner.http_prober import ProbeResult

logger = logging.getLogger(__name__)


class FingerprintEngine:

    def __init__(self):
        self._loader = FingerprintLoader()
        self._exclusion_filter: ExclusionFilter | None = None

    @property
    def loader(self) -> FingerprintLoader:
        return self._loader

    def load(self) -> None:
        self._loader.load()
        self._exclusion_filter = ExclusionFilter(self._loader.exclusion_list)
        logger.info(
            "FingerprintEngine loaded: %d rules, %d exclusions",
            len(self._loader.rule_list),
            len(self._loader.exclusion_list),
        )

    def reload(self) -> None:
        self.load()

    def match(self, probe: ProbeResult) -> MatchResult | None:
        response_map = _build_response_map(probe)
        matched_entry_list: list[tuple[FingerprintRule, MatchResult]] = []

        for rule in self._loader.rule_list:
            result = rule.evaluate(response_map)
            if result:
                matched_entry_list.append((rule, result))

        if matched_entry_list:
            result = _aggregate_match_result(matched_entry_list)
            logger.debug(
                "Matched %s:%d -> %s (rules=%s, score=%d)",
                probe.ip,
                probe.port,
                result.claw_type,
                ",".join(result.matched_rule_list),
                result.confidence_score,
            )
            return result

        if self._exclusion_filter and self._exclusion_filter.should_exclude(probe):
            logger.debug("Excluded %s:%d after rule miss", probe.ip, probe.port)

        return None

    def match_all(self, probe_list: list[ProbeResult]) -> list[tuple[ProbeResult, MatchResult]]:
        matched_list: list[tuple[ProbeResult, MatchResult]] = []
        for probe in probe_list:
            result = self.match(probe)
            if result:
                matched_list.append((probe, result))
        return matched_list


def _build_response_map(probe: ProbeResult) -> dict[str, dict]:
    response_map: dict[str, dict] = {}
    for resp in probe.response_list:
        response_map[resp.path] = {
            "status_code": resp.status_code,
            "headers": resp.headers,
            "body": resp.body,
            "title": resp.title,
            "content_type": resp.content_type,
            "body_hash": resp.body_hash,
            "asset_path_list": resp.asset_path_list,
            "app_hint_list": resp.app_hint_list,
        }
    response_map["__meta__"] = {
        "ws_available": probe.ws_available,
        "sse_available": probe.sse_available,
        "ip": probe.ip,
        "port": probe.port,
        "peer_port_list": probe.peer_port_list,
        "nmap_service": probe.nmap_service,
        "nmap_version": probe.nmap_version,
        "nse_output": probe.nse_output,
    }
    return response_map


def _aggregate_match_result(
    matched_entry_list: list[tuple[FingerprintRule, MatchResult]],
) -> MatchResult:
    family_bucket_map: dict[str, dict] = defaultdict(
        lambda: {
            "score": 0,
            "max_priority": 0,
            "confirmed": False,
            "keyword_set": set(),
            "rule_id_list": [],
            "variant_score_map": defaultdict(int),
            "version": None,
            "best_single": None,
        }
    )

    for rule, result in matched_entry_list:
        family = result.family_hint or result.claw_type
        bucket = family_bucket_map[family]
        bucket["score"] += result.confidence_score
        bucket["max_priority"] = max(bucket["max_priority"], rule.priority)
        bucket["confirmed"] = bucket["confirmed"] or result.confidence == "CONFIRMED"
        if result.matched_keyword:
            bucket["keyword_set"].update(
                part.strip() for part in result.matched_keyword.split(",") if part.strip()
            )
        if result.matched_rule not in bucket["rule_id_list"]:
            bucket["rule_id_list"].append(result.matched_rule)
        if result.variant_hint:
            bucket["variant_score_map"][result.variant_hint] += result.confidence_score
        if result.claw_version and not bucket["version"]:
            bucket["version"] = result.claw_version
        if (
            bucket["best_single"] is None
            or result.confidence_score > bucket["best_single"].confidence_score
            or (
                result.confidence_score == bucket["best_single"].confidence_score
                and rule.priority > bucket["max_priority"]
            )
        ):
            bucket["best_single"] = result

    best_family, best_bucket = max(
        family_bucket_map.items(),
        key=lambda item: (
            1 if item[1]["confirmed"] else 0,
            item[1]["score"],
            item[1]["max_priority"],
            len(item[1]["rule_id_list"]),
        ),
    )
    best_single = best_bucket["best_single"]
    variant_hint = None
    if best_bucket["variant_score_map"]:
        variant_hint = max(
            best_bucket["variant_score_map"].items(),
            key=lambda item: item[1],
        )[0]

    confidence_bonus = min(12, max(len(best_bucket["rule_id_list"]) - 1, 0) * 3)
    return MatchResult(
        claw_type=best_family,
        claw_version=best_bucket["version"] or best_single.claw_version,
        confidence="CONFIRMED" if best_bucket["confirmed"] else "SUSPECTED",
        confidence_score=min(99, best_single.confidence_score + confidence_bonus),
        matched_keyword=", ".join(sorted(best_bucket["keyword_set"])[:5]),
        matched_rule=best_single.matched_rule,
        matched_rule_list=best_bucket["rule_id_list"],
        family_hint=best_family,
        variant_hint=variant_hint or best_single.variant_hint,
    )
