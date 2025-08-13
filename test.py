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
from univers.version_range import GenericVersionRange
from univers.versions import SemverVersion

from agent import VulnerabilityAgent


def test_simple_vulnerability_summary_parser():
    summary = """Off-by-one error in the apr_brigade_vprintf function in Apache APR-util before 1.3.5
              on big-endian platforms allows remote attackers to obtain sensitive information or cause a
              denial of service (application crash) via crafted input."""

    instance = VulnerabilityAgent()
    purl = instance.get_purl_from_summary(summary)
    version_ranges = instance.get_version_ranges(
        summary, purl.type
    )  # [affected_versions, fixed_versions]

    assert str(purl) == "pkg:generic/apache-apr-util@1.3.5"
    assert version_ranges == (
        [
            GenericVersionRange(
                constraints=(
                    VersionConstraint(
                        comparator="<", version=SemverVersion(string="1.3.5")
                    ),
                )
            )
        ],
        [
            GenericVersionRange(
                constraints=(
                    VersionConstraint(
                        comparator="=", version=SemverVersion(string="1.3.5")
                    ),
                )
            )
        ],
    )


@pytest.mark.parametrize(
    "cpe, pkg_type, expected_purl",
    [
        (
            "cpe:2.3:a:django-helpdesk_project:django-helpdesk:-:*:*:*:*:*:*:*",
            "pypi",
            "pkg:pypi/django-helpdesk",
        ),
    ],
)
def test_vulnerability_cpe_parser_varied_ecosystems(cpe, pkg_type, expected_purl):
    agent = VulnerabilityAgent()
    purl = agent.get_purl_from_cpe(cpe, pkg_type)
    assert str(purl) == expected_purl
