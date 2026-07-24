# SPDX-License-Identifier: Apache-2.0
"""PURL identity — the distinction that makes version drift readable."""

from __future__ import annotations

import pytest

from sbomdrift.models import (
    Component,
    Finding,
    normalise_purl_case,
    purl_identity,
    purl_version,
    severity_rank,
)


@pytest.mark.parametrize(
    ("purl", "identity", "version"),
    [
        ("pkg:pypi/requests@2.31.0", "pkg:pypi/requests", "2.31.0"),
        ("pkg:deb/debian/openssl@3.5.6-1~deb13u2", "pkg:deb/debian/openssl", "3.5.6-1~deb13u2"),
        ("pkg:deb/Debian/libzstd@1.5.7%2Bdfsg-1", "pkg:deb/debian/libzstd", "1.5.7%2Bdfsg-1"),
        ("pkg:golang/github.com/x/y@v1.2.3", "pkg:golang/github.com/x/y", "v1.2.3"),
        ("pkg:generic/no-version", "pkg:generic/no-version", ""),
    ],
)
def test_identity_and_version_split(purl, identity, version):
    assert purl_identity(purl) == identity
    assert purl_version(purl) == version


def test_qualifiers_do_not_reach_the_identity():
    assert purl_identity("pkg:deb/debian/zlib1g@1.2?arch=amd64") == "pkg:deb/debian/zlib1g"


def test_an_upgrade_preserves_identity():
    """The property the whole drift comparison depends on."""
    old = Component("pkg:deb/debian/openssl@1.1.1n-0+deb11u3", "openssl", "1.1.1n-0+deb11u3")
    new = Component("pkg:deb/debian/openssl@3.5.6-1~deb13u2", "openssl", "3.5.6-1~deb13u2")
    assert old.identity == new.identity


def test_findings_on_the_same_package_across_versions_share_a_key():
    """Otherwise every upgrade reports the entire backlog as fixed and re-found."""
    before = Finding(purl="pkg:deb/debian/openssl@1.1.1n", vuln_id="CVE-2022-1234")
    after = Finding(purl="pkg:deb/debian/openssl@3.5.6", vuln_id="CVE-2022-1234")
    assert before.key == after.key


def test_findings_on_different_packages_do_not_collide():
    a = Finding(purl="pkg:deb/debian/openssl@3.5.6", vuln_id="CVE-2022-1234")
    b = Finding(purl="pkg:deb/debian/curl@8.0", vuln_id="CVE-2022-1234")
    assert a.key != b.key


def test_normalise_purl_case_leaves_the_package_name_alone():
    """Only type and namespace are case-insensitive; the name can be meaningful."""
    assert normalise_purl_case("pkg:npm/@ScopedOrg/MyPkg") == "pkg:npm/@scopedorg/MyPkg"
    assert normalise_purl_case("pkg:pypi/Django") == "pkg:pypi/Django"


def test_component_ecosystem():
    assert Component("pkg:pypi/requests@2.31.0", "requests", "2.31.0").ecosystem == "pypi"
    assert Component("not-a-purl", "x", "1").ecosystem == "unknown"


@pytest.mark.parametrize(
    ("severity", "expected"),
    [("CRITICAL", 5), ("high", 4), ("Medium", 3), ("LOW", 2), ("nonsense", 0)],
)
def test_severity_rank_is_case_insensitive(severity, expected):
    assert severity_rank(severity) == expected
