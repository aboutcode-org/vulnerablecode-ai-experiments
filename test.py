#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode.ai is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import pytest
from univers.version_constraint import VersionConstraint
from univers.version_range import PypiVersionRange
from univers.versions import PypiVersion

from agent import VulnerabilityAgent


@pytest.mark.parametrize(
    "summary, expected_purl, expected_version_ranges",
    [
        (
            """ReactPHP's HTTP server continues parsing unused multipart parts after reaching input field and file upload limits """,
            "pkg:composer/react/http",
            ([], []),
        ),
        (
            """A flaw was found in ansible. Credentials, such as secrets, are being disclosed in console log by default and not protected by no_log feature when using those modules. An attacker can take advantage of this information to steal those credentials. The highest threat from this vulnerability is to data confidentiality. Versions before ansible 2.9.18 are affected. """,
            "pkg:pypi/ansible",
            (
                [
                    PypiVersionRange(
                        constraints=(
                            VersionConstraint(
                                comparator="<", version=PypiVersion(string="2.9.18")
                            ),
                        )
                    )
                ],
                [
                    PypiVersionRange(
                        constraints=(
                            VersionConstraint(
                                comparator=">=", version=PypiVersion(string="2.9.18")
                            ),
                        )
                    )
                ],
            ),
        ),
    ],
)
def test_simple_vulnerability_summary_parser(
    summary, expected_purl, expected_version_ranges
):
    instance = VulnerabilityAgent()
    purl = instance.get_purl_from_summary(summary)
    version_ranges = instance.get_version_ranges(
        summary, purl.type
    )  # [affected_versions, fixed_versions]

    assert str(purl) == expected_purl
    assert version_ranges == expected_version_ranges


@pytest.mark.parametrize(
    "cpe, pkg_type, expected_purl",
    [
        (
            "cpe:2.3:a:django-helpdesk_project:django-helpdesk:-:*:*:*:*:*:*:*",
            "pypi",
            "pkg:pypi/django-helpdesk",
        ),
        (
            "cpe:2.3:a:node-simple-router:node-simple-router:0.1.4:*:*:*:*:node.js:*:*",
            "npm",
            "pkg:npm/node-simple-router",
        ),
        (
            "cpe:2.3:a:facebook:folly:2020.07.13.00:*:*:*:*:*:*:*",
            "github",
            "pkg:github/facebook/folly",
        ),
    ],
)
def test_vulnerability_cpe_parser_varied_ecosystems(cpe, pkg_type, expected_purl):
    agent = VulnerabilityAgent()
    purl = agent.get_purl_from_cpe(cpe, pkg_type)
    assert str(purl) == expected_purl


@pytest.mark.parametrize(
    "summary, expected_severity",
    [
        (
            """
            Git is a fast, scalable, distributed revision control system with an unusually rich command set that provides
            both high-level operations and full access to internals. When reading a config value, Git strips any
            trailing carriage return and line feed (CRLF). When writing a config entry, values with a trailing CR are not quoted,
            causing the CR to be lost when the config is later read. When initializing a submodule,
            if the submodule path contains a trailing CR, the altered path is read resulting in the submodule being checked out to an incorrect location.
            If a symlink exists that points the altered path to the submodule hooks directory,
            and the submodule contains an executable post-checkout hook, the script may be unintentionally executed after checkout.
            This vulnerability is fixed in v2.43.7, v2.44.4, v2.45.4, v2.46.4, v2.47.3, v2.48.2, v2.49.1, and v2.50.1.
            """,
            "high",
        ),
        (
            "The ShortPixel Image Optimizer – Optimize Images, Convert WebP & AVIF plugin for WordPress is vulnerable to unauthorized modification of data due to a missing capability check on the 'shortpixel_ajaxRequest' AJAX action in all versions up to, and including, 6.3.4. This makes it possible for authenticated attackers, with Contributor-level access and above, to export and import site options.",
            "medium",
        ),
    ],
)
def test_vulnerability_severity_parser(summary, expected_severity):
    agent = VulnerabilityAgent()
    severity = agent.get_severity_from_summary(summary)
    assert str(severity) == expected_severity


@pytest.mark.parametrize(
    "summary, expected_cwe_list",
    [
        (
            """
            Deserialization of untrusted data in Microsoft Office SharePoint allows an authorized attacker to execute code over a network.
            """,
            ["CWE-502"],
        ),
    ],
)
def test_vulnerability_cwe_parser(summary, expected_cwe_list):
    agent = VulnerabilityAgent()
    cwe_list = agent.get_cwe_from_summary(summary)
    assert cwe_list == expected_cwe_list
