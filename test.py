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
from agent import VulnerabilitySummaryParser, CPEParser


def test_simple_vulnerability_summary_parser():
    summary="""Off-by-one error in the apr_brigade_vprintf function in Apache APR-util before 1.3.5
              on big-endian platforms allows remote attackers to obtain sensitive information or cause a
              denial of service (application crash) via crafted input."""

    instance = VulnerabilitySummaryParser()
    purl = instance.get_purl(summary)
    version_ranges = instance.get_version_ranges(summary, purl.type) # [affected_versions, fixed_versions]

    assert str(purl) == 'pkg:generic/apache-apr-util@1.3.5'
    assert version_ranges == (
        [GenericVersionRange(constraints=(VersionConstraint(comparator='<', version=SemverVersion(string='1.3.5')),))],
        [GenericVersionRange(constraints=(VersionConstraint(comparator='=', version=SemverVersion(string='1.3.5')),))]
    )


def test_simple_vulnerability_cpe_parser():
    cpe = """cpe:2.3:a:djangoproject:django:1.8.0:*:*:*:*:*:*:*"""

    instance = CPEParser()
    purl = instance.get_purl(cpe)

    assert str(purl) == 'pkg:pypi/django@1.8.0'

