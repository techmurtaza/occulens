"""PII and named entity detector combining Microsoft Presidio and spaCy NER.

Detects persons, email addresses, phone numbers, locations, organizations,
URLs, and financial/identification account identifiers in raw text context.
"""

from __future__ import annotations

import functools
import re
from typing import Any

import spacy
import tldextract.tldextract
from presidio_analyzer import AnalyzerEngine, RecognizerResult
from presidio_analyzer.nlp_engine import NlpEngineProvider, SpacyNlpEngine
from spacy.language import Language

from occulens.domain.models import DetectedEntity, EntityType

# Enforce local-first execution by disabling remote suffix list downloads
tldextract.tldextract.TLD_EXTRACTOR.suffix_list_urls = ()

_PRESIDIO_TO_DOMAIN_MAP: dict[str, EntityType] = {
    "EMAIL_ADDRESS": EntityType.EMAIL,
    "EMAIL": EntityType.EMAIL,
    "PHONE_NUMBER": EntityType.PHONE,
    "URL": EntityType.URL,
    "PERSON": EntityType.PERSON,
    "LOCATION": EntityType.LOCATION,
    "ORGANIZATION": EntityType.ORGANIZATION,
    "CREDIT_CARD": EntityType.ACCOUNT_ID,
    "CRYPTO": EntityType.ACCOUNT_ID,
    "IBAN_CODE": EntityType.ACCOUNT_ID,
    "IP_ADDRESS": EntityType.ACCOUNT_ID,
    "US_BANK_NUMBER": EntityType.ACCOUNT_ID,
    "US_DRIVER_LICENSE": EntityType.ACCOUNT_ID,
    "US_ITIN": EntityType.ACCOUNT_ID,
    "US_PASSPORT": EntityType.ACCOUNT_ID,
    "US_SSN": EntityType.ACCOUNT_ID,
    "UK_NHS": EntityType.ACCOUNT_ID,
    "MEDICAL_LICENSE": EntityType.ACCOUNT_ID,
}

_SPACY_TO_DOMAIN_MAP: dict[str, EntityType] = {
    "PERSON": EntityType.PERSON,
    "ORG": EntityType.ORGANIZATION,
    "GPE": EntityType.LOCATION,
    "LOC": EntityType.LOCATION,
    "FAC": EntityType.LOCATION,
    "PRODUCT": EntityType.PROJECT,
}

_STRUCTURED_PII_TYPES: frozenset[EntityType] = frozenset(
    {
        EntityType.EMAIL,
        EntityType.PHONE,
        EntityType.URL,
        EntityType.ACCOUNT_ID,
    }
)

_NER_TYPES: frozenset[EntityType] = frozenset(
    {
        EntityType.PERSON,
        EntityType.ORGANIZATION,
        EntityType.LOCATION,
        EntityType.PROJECT,
    }
)

_URL_TRAILING_PUNCTUATION = re.compile(r"[.,;:!?]+$")


@functools.cache
def _get_analyzer_and_nlp() -> tuple[AnalyzerEngine, Language]:
    """Initialize and cache the Presidio AnalyzerEngine and shared spaCy pipeline.

    Tries en_core_web_md first per ADR-003, falling back to en_core_web_sm.
    Raises RuntimeError if neither model is installed.
    """
    model_name = "en_core_web_md"
    try:
        spacy.load(model_name)
    except OSError:
        model_name = "en_core_web_sm"
        try:
            spacy.load(model_name)
        except OSError as err:
            raise RuntimeError(
                "Neither spaCy model 'en_core_web_md' nor 'en_core_web_sm' is installed. "
                "Please run: python -m spacy download en_core_web_md"
            ) from err

    configuration: dict[str, Any] = {
        "nlp_engine_name": "spacy",
        "models": [{"lang_code": "en", "model_name": model_name}],
    }
    provider = NlpEngineProvider(nlp_configuration=configuration)
    nlp_engine = provider.create_engine()
    if (
        not isinstance(nlp_engine, SpacyNlpEngine)
        or nlp_engine.nlp is None
        or "en" not in nlp_engine.nlp
    ):
        raise RuntimeError("Failed to initialize SpacyNlpEngine with English pipeline")
    analyzer = AnalyzerEngine(nlp_engine=nlp_engine, supported_languages=["en"])
    spacy_nlp: Language = nlp_engine.nlp["en"]
    return analyzer, spacy_nlp


def _clean_span(text: str, start: int, end: int, entity_type: EntityType) -> tuple[int, int]:
    """Clean span boundaries, removing trailing sentence punctuation from URLs."""
    if entity_type == EntityType.URL:
        raw_val = text[start:end]
        match = _URL_TRAILING_PUNCTUATION.search(raw_val)
        if match:
            end -= match.end() - match.start()
    return start, end


def _arbitrate_and_deduplicate(candidates: list[DetectedEntity]) -> list[DetectedEntity]:
    """Merge overlapping detections from Presidio and spaCy.

    Precedence rules:
    1. Higher confidence wins.
    2. Ties broken by preferring Presidio for structured PII and spaCy for NER.
    3. Ties broken by longer span length.
    4. Earlier start offset.
    """
    if not candidates:
        return []

    def _priority_key(entity: DetectedEntity) -> tuple[float, int, int, int]:
        """Compute sort priority tuple for interval arbitration."""
        is_structured_pii = entity.entity_type in _STRUCTURED_PII_TYPES and entity.source in (
            "presidio",
            "regex",
        )
        is_preferred_ner = entity.entity_type in _NER_TYPES and entity.source == "spacy"
        is_preferred_source = 1 if (is_structured_pii or is_preferred_ner) else 0

        span_len = entity.end - entity.start
        return (entity.confidence, is_preferred_source, span_len, -entity.start)

    sorted_candidates = sorted(candidates, key=_priority_key, reverse=True)
    selected: list[DetectedEntity] = []

    for cand in sorted_candidates:
        overlaps = False
        for s in selected:
            # Two half-open intervals [a, b) and [c, d) overlap if max(a, c) < min(b, d)
            if max(cand.start, s.start) < min(cand.end, s.end):
                overlaps = True
                break
        if not overlaps:
            selected.append(cand)

    return sorted(selected, key=lambda e: (e.start, e.end))


def detect_pii(text: str) -> list[DetectedEntity]:
    """Scan text for PII and named entities using Presidio and spaCy NER.

    This function detects persons, emails, phones, locations, organizations,
    URLs, and identifiers. Overlapping spans are arbitrated and deduplicated.

    Args:
        text: The raw input string to inspect.

    Returns:
        A list of DetectedEntity objects, sorted by starting character offset.
    """
    if not text or not text.strip():
        return []

    analyzer, _ = _get_analyzer_and_nlp()
    candidates: list[DetectedEntity] = []

    # 1. Single-pass NLP processing shared between Presidio and spaCy NER
    nlp_artifacts = analyzer.nlp_engine.process_text(text, language="en")
    presidio_results: list[RecognizerResult] = analyzer.analyze(
        text=text,
        language="en",
        score_threshold=0.4,
        nlp_artifacts=nlp_artifacts,
    )

    for res in presidio_results:
        entity_type = _PRESIDIO_TO_DOMAIN_MAP.get(res.entity_type)
        if entity_type is None:
            continue

        start, end = _clean_span(text, res.start, res.end, entity_type)
        if end <= start:
            continue

        # Attribute source: SpacyRecognizer results originate from spaCy NER
        recognizer_name = res.recognition_metadata.get("recognizer_name", "")
        source = "spacy" if recognizer_name == "SpacyRecognizer" else "presidio"

        candidates.append(
            DetectedEntity(
                entity_type=entity_type,
                start=start,
                end=end,
                confidence=round(float(res.score), 2),
                source=source,
                value=text[start:end],
            )
        )

    # 2. Extract language entities & products from the same parsed spaCy pass
    for ent in nlp_artifacts.entities:
        entity_type = _SPACY_TO_DOMAIN_MAP.get(ent.label_)
        if entity_type is None:
            continue

        start, end = _clean_span(text, ent.start_char, ent.end_char, entity_type)
        if end <= start:
            continue

        candidates.append(
            DetectedEntity(
                entity_type=entity_type,
                start=start,
                end=end,
                confidence=0.85,
                source="spacy",
                value=text[start:end],
            )
        )

    return _arbitrate_and_deduplicate(candidates)
