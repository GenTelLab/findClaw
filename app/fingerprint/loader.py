import json
import logging
from pathlib import Path

from app.config import settings
from app.fingerprint.rule import Condition, FingerprintRule, VersionExtract

logger = logging.getLogger(__name__)


class FingerprintLoader:

    def __init__(self):
        self._rule_list: list[FingerprintRule] = []
        self._exclusion_list: list[dict] = []

    @property
    def rule_list(self) -> list[FingerprintRule]:
        return self._rule_list

    @property
    def exclusion_list(self) -> list[dict]:
        return self._exclusion_list

    def load(self) -> None:
        self._rule_list = []
        self._exclusion_list = []

        builtin_path = Path(settings.fingerprint_builtin_path)
        if builtin_path.exists():
            self._load_file(builtin_path)
            logger.info("Loaded builtin fingerprints: %d rules", len(self._rule_list))

        if settings.fingerprint_external_path:
            ext_path = Path(settings.fingerprint_external_path)
            if ext_path.exists():
                count_before = len(self._rule_list)
                self._load_file(ext_path)
                logger.info(
                    "Loaded external fingerprints: %d rules",
                    len(self._rule_list) - count_before,
                )

        self._rule_list.sort(key=lambda r: r.priority, reverse=True)

    def _load_file(self, path: Path) -> None:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)

        for rule_data in data.get("rules", []):
            rule = _parse_rule(rule_data)
            if rule:
                self._rule_list.append(rule)

        for exc in data.get("exclusions", []):
            self._exclusion_list.append(exc)

    def get_rule_summary_list(self) -> list[dict]:
        return [
            {
                "id": r.id,
                "name": r.name,
                "category": r.category,
                "priority": r.priority,
                "confidence_score": r.confidence_score,
            }
            for r in self._rule_list
        ]


def _parse_rule(data: dict) -> FingerprintRule | None:
    try:
        conditions = data.get("conditions", {})
        mode = "anyOf" if "anyOf" in conditions else "allOf"
        raw_condition_list = conditions.get(mode, [])

        condition_list = [
            Condition(
                type=c.get("type", ""),
                path=c.get("path", ""),
                method=c.get("method", "GET"),
                header_name=c.get("headerName", ""),
                match=c.get("match", {}),
            )
            for c in raw_condition_list
        ]

        ve_data = data.get("versionExtract")
        version_extract = None
        if ve_data:
            version_extract = VersionExtract(
                source=ve_data.get("from", "header"),
                header_name=ve_data.get("headerName", ""),
                regex=ve_data.get("regex", ""),
            )

        return FingerprintRule(
            id=data["id"],
            name=data["name"],
            category=data.get("category", "suspected"),
            priority=data.get("priority", 0),
            family_name=data.get("familyName", data.get("name", "")),
            variant_name=data.get("variantName"),
            condition_list=condition_list,
            condition_mode=mode,
            version_extract=version_extract,
            confidence_score=data.get("confidenceScore", 50),
        )
    except (KeyError, TypeError) as e:
        logger.warning("Failed to parse rule: %s", e)
        return None
