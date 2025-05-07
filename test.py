import pytest
from univers.version_constraint import VersionConstraint
from univers.version_range import GenericVersionRange
from univers.versions import SemverVersion
from agent import VulnerabilitySummaryParser


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
