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
from univers.version_range import MavenVersionRange, PypiVersionRange
from univers.versions import MavenVersion, PypiVersion

from agent import VulnerabilityAgent


@pytest.mark.parametrize(
    "summary, expected_purl, expected_version_ranges",
    [
        (
            """Off-by-one error in the apr_brigade_vprintf function in Apache APR-util before 1.3.5
                          on big-endian platforms allows remote attackers to obtain sensitive information or cause a
                          denial of service (application crash) via crafted input.""",
            "pkg:maven/org.apache.apr/apr-util",
            (
            [MavenVersionRange(constraints=(VersionConstraint(comparator='<', version=MavenVersion(string='1.3.5')),))],
            [MavenVersionRange(constraints=(VersionConstraint(comparator='>=', version=MavenVersion(string='1.3.5')),))])
        ),
        (
           """A maliciously crafted URL to a Django (1.10 before 1.10.7, 1.9 before 1.9.13, and 1.8 before 1.8.18) site using the ``django.views.static.serve()`` view could redirect to any other domain, aka an open redirect vulnerability. """,
           "pkg:pypi/django",
           (([PypiVersionRange(constraints=(VersionConstraint(comparator='>=', version=PypiVersion(string='1.10')),)),
              PypiVersionRange(constraints=(VersionConstraint(comparator='<', version=PypiVersion(string='1.10.7')),)),
              PypiVersionRange(constraints=(VersionConstraint(comparator='>=', version=PypiVersion(string='1.9')),)),
              PypiVersionRange(constraints=(VersionConstraint(comparator='<', version=PypiVersion(string='1.9.13')),)),
              PypiVersionRange(constraints=(VersionConstraint(comparator='>=', version=PypiVersion(string='1.8')),)),
              PypiVersionRange(constraints=(VersionConstraint(comparator='<', version=PypiVersion(string='1.8.18')),))],
             [PypiVersionRange(constraints=(VersionConstraint(comparator='>=', version=PypiVersion(string='1.10.7')),)),
              PypiVersionRange(constraints=(VersionConstraint(comparator='>=', version=PypiVersion(string='1.9.13')),)),
              PypiVersionRange(constraints=(VersionConstraint(comparator='>=', version=PypiVersion(string='1.8.18')),))]))
        ),
        (
            """ReactPHP's HTTP server continues parsing unused multipart parts after reaching input field and file upload limits """,
            "pkg:composer/react/http",
            ([], [])
        ),
        (
            """A flaw was found in ansible. Credentials, such as secrets, are being disclosed in console log by default and not protected by no_log feature when using those modules. An attacker can take advantage of this information to steal those credentials. The highest threat from this vulnerability is to data confidentiality. Versions before ansible 2.9.18 are affected. """ ,
            "pkg:pypi/ansible",
            ([PypiVersionRange(constraints=(VersionConstraint(comparator='<', version=PypiVersion(string='2.9.18')),))],
             [PypiVersionRange(
                 constraints=(VersionConstraint(comparator='>=', version=PypiVersion(string='2.9.18')),))]),
        )
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
