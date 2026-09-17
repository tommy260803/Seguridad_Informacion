from pathlib import Path

import pytest

from phishguard_data.psl import PublicSuffixList
from phishguard_data.urls import UrlValidationError, canonicalize_url


@pytest.fixture
def psl() -> PublicSuffixList:
    return PublicSuffixList.from_file(Path("tests/fixtures/public_suffix_list.dat"))


def test_canonicalize_normalizes_without_reordering_query(psl: PublicSuffixList) -> None:
    result = canonicalize_url(" HTTPS://ExAmPle.COM:443/%7euser?a=2&a=1#fragment ", psl)

    assert result.value == "https://example.com/~user?a=2&a=1"
    assert result.registered_domain == "example.com"
    assert result.has_userinfo is False


def test_canonicalize_preserves_userinfo_as_a_feature(psl: PublicSuffixList) -> None:
    result = canonicalize_url("http://brand.example@evil.co.uk/login", psl)

    assert result.host == "evil.co.uk"
    assert result.registered_domain == "evil.co.uk"
    assert result.has_userinfo is True


@pytest.mark.parametrize("url", ["file:///tmp/x", "https://", "https://bad.example/\nnext"])
def test_canonicalize_rejects_invalid_urls(psl: PublicSuffixList, url: str) -> None:
    with pytest.raises(UrlValidationError):
        canonicalize_url(url, psl)


def test_psl_wildcard_and_exception_rules(psl: PublicSuffixList) -> None:
    assert psl.registrable_domain("a.b.ck") == "a.b.ck"
    assert psl.registrable_domain("foo.www.ck") == "www.ck"
    assert psl.registrable_domain("sub.example.co.uk") == "example.co.uk"
    assert psl.registrable_domain("192.0.2.10") == "192.0.2.10"
