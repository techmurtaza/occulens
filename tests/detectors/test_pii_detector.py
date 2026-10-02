"""Unit tests for the PII and named entity detector (Presidio + spaCy NER).

Tests verify detection of persons, emails, phones, locations, organizations,
URLs, accounts, Unicode handling, and span arbitration.
"""

from __future__ import annotations

from occulens.detectors import detect_pii, detect_secrets
from occulens.domain.models import DetectedEntity, EntityType


def test_detect_email() -> None:
    text = "Send reports to alice.smith@example.org or support+dev@sub.company.co."
    results = detect_pii(text)
    emails = [e for e in results if e.entity_type == EntityType.EMAIL]

    assert len(emails) == 2
    assert emails[0].value == "alice.smith@example.org"
    assert emails[0].source == "presidio"
    assert emails[0].confidence >= 0.8
    assert emails[1].value == "support+dev@sub.company.co"
    assert emails[1].source == "presidio"


def test_detect_phone() -> None:
    text = "Call office at 555-123-4567 or international line +1 (415) 555-2671 today."
    results = detect_pii(text)
    phones = [e for e in results if e.entity_type == EntityType.PHONE]

    assert len(phones) >= 2
    values = [p.value for p in phones]
    assert any("555-123-4567" in v for v in values)
    assert any("555-2671" in v for v in values)
    for p in phones:
        assert p.source == "presidio"


def test_detect_person() -> None:
    text = "Project coordinator John Doe met with lead engineer Sarah Connor yesterday."
    results = detect_pii(text)
    persons = [e for e in results if e.entity_type == EntityType.PERSON]

    assert len(persons) == 2
    values = [p.value for p in persons]
    assert "John Doe" in values
    assert "Sarah Connor" in values
    for p in persons:
        assert p.source == "spacy"
        assert p.confidence >= 0.8


def test_detect_organization() -> None:
    text = "Acme Corp announced an enterprise partnership with Microsoft."
    results = detect_pii(text)
    orgs = [e for e in results if e.entity_type == EntityType.ORGANIZATION]

    assert len(orgs) == 2
    values = [o.value for o in orgs]
    assert "Acme Corp" in values
    assert "Microsoft" in values
    for o in orgs:
        assert o.source == "spacy"


def test_detect_location() -> None:
    text = "The conference took place in Paris and Tokyo before moving to California."
    results = detect_pii(text)
    locations = [e for e in results if e.entity_type == EntityType.LOCATION]

    values = [loc.value for loc in locations]
    assert "Paris" in values
    assert "Tokyo" in values
    assert "California" in values
    for loc in locations:
        assert loc.source == "spacy"


def test_detect_url_and_trim_punctuation() -> None:
    text = "Documentation is at https://docs.example.com/api/v1, or visit https://portal.internal.net."
    results = detect_pii(text)
    urls = [e for e in results if e.entity_type == EntityType.URL]

    assert len(urls) == 2
    assert urls[0].value == "https://docs.example.com/api/v1"
    assert urls[1].value == "https://portal.internal.net"
    for u in urls:
        assert not u.value.endswith((".", ",", ";"))
        assert u.source == "presidio"


def test_detect_account_id_and_ip() -> None:
    text = "Server internal IP address 192.168.1.100 was reported in ticket."
    results = detect_pii(text)
    accounts = [e for e in results if e.entity_type == EntityType.ACCOUNT_ID]

    assert len(accounts) >= 1
    assert any("192.168.1.100" in a.value for a in accounts)


def test_detect_unicode_names() -> None:
    text = "Consultant François Müller visited the team in Zürich."
    results = detect_pii(text)

    persons = [e for e in results if e.entity_type == EntityType.PERSON]
    assert any("François Müller" in p.value for p in persons)

    locations = [e for e in results if e.entity_type == EntityType.LOCATION]
    assert any("Zürich" in loc.value for loc in locations)


def test_empty_and_whitespace_input() -> None:
    assert detect_pii("") == []
    assert detect_pii("   ") == []
    assert detect_pii("\n\t  \r\n") == []


def test_text_with_no_pii() -> None:
    text = "The quick brown fox jumps over the lazy dog in autumn."
    assert detect_pii(text) == []


def test_entities_at_string_boundaries() -> None:
    text = "Alice went to Paris"
    results = detect_pii(text)

    assert results[0].value == "Alice"
    assert results[0].start == 0
    assert results[0].entity_type == EntityType.PERSON

    assert results[-1].value == "Paris"
    assert results[-1].end == len(text)
    assert results[-1].entity_type == EntityType.LOCATION


def test_overlapping_email_and_url_suppression() -> None:
    # An email contains a domain that matches URL patterns.
    # The email should take precedence, suppressing the inner URL span.
    text = "Contact satya@microsoft.com for official inquiries."
    results = detect_pii(text)

    emails = [e for e in results if e.entity_type == EntityType.EMAIL]
    urls = [e for e in results if e.entity_type == EntityType.URL]

    assert len(emails) == 1
    assert emails[0].value == "satya@microsoft.com"
    # The domain inside the email address should not be emitted as a separate URL
    assert not any(u.value == "microsoft.com" for u in urls)


def test_arbitration_longer_span_preference() -> None:
    from occulens.detectors.pii_detector import _arbitrate_and_deduplicate

    e1 = DetectedEntity(
        entity_type=EntityType.LOCATION,
        start=0,
        end=8,
        confidence=0.85,
        source="spacy",
        value="New York",
    )
    e2 = DetectedEntity(
        entity_type=EntityType.ORGANIZATION,
        start=0,
        end=14,
        confidence=0.85,
        source="spacy",
        value="New York Times",
    )

    arbitrated = _arbitrate_and_deduplicate([e1, e2])
    assert len(arbitrated) == 1
    assert arbitrated[0].value == "New York Times"
    assert arbitrated[0].entity_type == EntityType.ORGANIZATION


def test_arbitration_structured_pii_preference_on_equal_confidence() -> None:
    from occulens.detectors.pii_detector import _arbitrate_and_deduplicate

    # Equal confidence tie between structured PII (Presidio) and NER (spaCy)
    e1 = DetectedEntity(
        entity_type=EntityType.EMAIL,
        start=0,
        end=15,
        confidence=0.85,
        source="presidio",
        value="user@domain.com",
    )
    e2 = DetectedEntity(
        entity_type=EntityType.PERSON,
        start=0,
        end=15,
        confidence=0.85,
        source="spacy",
        value="User Domain Com",
    )

    arbitrated = _arbitrate_and_deduplicate([e1, e2])
    assert len(arbitrated) == 1
    assert arbitrated[0].entity_type == EntityType.EMAIL
    assert arbitrated[0].source == "presidio"


def test_pure_function_determinism() -> None:
    text = "Alice visited Microsoft headquarters in Redmond. Email: alice@microsoft.com."
    run_1 = detect_pii(text)
    run_2 = detect_pii(text)

    assert run_1 == run_2
    assert len(run_1) >= 4


def test_module_exports() -> None:
    import occulens.detectors as detectors

    assert hasattr(detectors, "detect_pii")
    assert hasattr(detectors, "detect_secrets")
    assert callable(detect_pii)
    assert callable(detect_secrets)
