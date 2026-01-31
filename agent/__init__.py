#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode.ai is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import os
from enum import Enum
from typing import List, Optional

from aboutcode.hashid import get_core_purl
from cwe2.database import Database
from dotenv import load_dotenv
from packageurl import PackageURL
from pydantic import BaseModel
from pydantic.functional_validators import field_validator
from pydantic_ai import Agent
from pydantic_ai.models.openai import OpenAIChatModel, OpenAIChatModelSettings
from pydantic_ai.providers.openai import OpenAIProvider
from univers.version_range import RANGE_CLASS_BY_SCHEMES

from prompts import (PROMPT_CWE_FROM_SUMMARY, PROMPT_PURL_FROM_CPE,
                     PROMPT_PURL_FROM_SUMMARY, PROMPT_SEVERITY_FROM_SUMMARY,
                     PROMPT_VERSION_FROM_SUMMARY)

load_dotenv()

OPENAI_API_BASE = os.getenv("OPENAI_API_BASE")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OPENAI_MODEL_NAME = os.getenv("OPENAI_MODEL_NAME")
OPENAI_TEMPERATURE = float(os.getenv("OPENAI_TEMPERATURE", "0.3"))
OPENAI_MODEL_SEED = int(os.getenv("OPENAI_MODEL_SEED", "11111111"))


class Purl(BaseModel):
    string: str

    @field_validator("string")
    def check_valid_purl(cls, purl: str) -> str:
        PackageURL.from_string(purl)
        return purl


CWE_DATABASE = Database()


class CWE(BaseModel):
    string: str

    @field_validator("string")
    @classmethod
    def check_valid_cwe(cls, v: str) -> str:
        norm = v.strip().upper()
        if norm.startswith("CWE-"):
            norm = norm[4:].strip()

        if not norm.isdigit():
            raise ValueError("CWE must be a numeric identifier, e.g., 'CWE-79' or '79'")

        CWE_DATABASE.get(norm)

        return f"CWE-{norm}"


class CWEList(BaseModel):
    cwes: List[CWE]


class SeverityEnum(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class Severity(BaseModel):
    severity: SeverityEnum


class Versions(BaseModel):
    affected_versions: List[str]
    fixed_versions: List[str]


class BaseParser:
    def __init__(self, system_prompt: str, output_type):
        self.model = self._init_model()
        self.agent = Agent(
            self.model,
            system_prompt=system_prompt,
            model_settings=OpenAIChatModelSettings(
                temperature=OPENAI_TEMPERATURE, seed=OPENAI_MODEL_SEED
            ),
            output_type=output_type,
        )

    @staticmethod
    def _init_model():
        """Initialize the LLM model depending on environment variables."""
        return OpenAIChatModel(
            model_name=OPENAI_MODEL_NAME,
            provider=OpenAIProvider(base_url=OPENAI_API_BASE, api_key=OPENAI_API_KEY),
        )

    def run_agent(self, user_prompt: str):
        """Run the agent synchronously."""
        return self.agent.run_sync(user_prompt=user_prompt)


class PurlFromSummaryParser(BaseParser):
    def __init__(self):
        super().__init__(PROMPT_PURL_FROM_SUMMARY, Purl)

    def get_purl(self, summary: str) -> Optional[PackageURL]:
        result = self.run_agent(f"**Vulnerability Summary:**\n{summary}")
        purl = PackageURL.from_string(result.output.string)
        return get_core_purl(purl)


class PurlFromCPEParser(BaseParser):
    def __init__(self):
        super().__init__(PROMPT_PURL_FROM_CPE, Purl)

    def get_purl(self, cpe: str, pkg_type) -> Optional[PackageURL]:
        result = self.run_agent(
            f"**Vulnerability Known Affected Software Configurations CPE:**\n{cpe}\n **Package Type:**\n{pkg_type}"
        )
        purl = PackageURL.from_string(result.output.string)
        return get_core_purl(purl)


class VersionsFromSummaryParser(BaseParser):
    def __init__(self):
        super().__init__(PROMPT_VERSION_FROM_SUMMARY, Versions)

    def get_version_ranges(self, summary: str, supported_ecosystem: str):
        result = self.run_agent(f"**Vulnerability Summary:**\n{summary}")
        affected_objs = [
            RANGE_CLASS_BY_SCHEMES[supported_ecosystem].from_string(
                f"vers:{supported_ecosystem}/{v}"
            )
            for v in result.output.affected_versions
        ]
        fixed_objs = [
            RANGE_CLASS_BY_SCHEMES[supported_ecosystem].from_string(
                f"vers:{supported_ecosystem}/{v}"
            )
            for v in result.output.fixed_versions
        ]
        return affected_objs, fixed_objs


class SeverityFromSummaryParser(BaseParser):
    def __init__(self):
        super().__init__(PROMPT_SEVERITY_FROM_SUMMARY, Severity)

    def get_severity(self, summary: str) -> Optional[Severity]:
        result = self.run_agent(f"**Vulnerability Description:**\n{summary}")
        return result.output.severity.value


class CWEFromSummaryParser(BaseParser):
    def __init__(self):
        super().__init__(PROMPT_CWE_FROM_SUMMARY, CWEList)

    def get_cwes(self, summary: str) -> List[CWEList]:
        result = self.run_agent(f"**Vulnerability Description:**\n{summary}")
        return [cwe.string for cwe in result.output.cwes]


class VulnerabilityAgent:
    """Unified interface for parsing vulnerability information.

    Handles extraction of PURLs, version ranges, severities, and CWEs
    from vulnerability summaries or CPE identifiers.
    """

    def __init__(self):
        self.purl_parser = PurlFromSummaryParser()
        self.versions_parser = VersionsFromSummaryParser()
        self.cpe_parser = PurlFromCPEParser()
        self.severity_parser = SeverityFromSummaryParser()
        self.cwe_parser = CWEFromSummaryParser()

    def get_purl_from_summary(self, summary: str):
        """Extract PURL from a vulnerability summary."""
        return self.purl_parser.get_purl(summary)

    def get_version_ranges(self, summary: str, ecosystem: str):
        """Extract affected version ranges from a summary."""
        return self.versions_parser.get_version_ranges(summary, ecosystem)

    def get_purl_from_cpe(self, cpe: str, pkg_type: str):
        """Convert a CPE string to a PURL."""
        return self.cpe_parser.get_purl(cpe, pkg_type)

    def get_severity_from_summary(self, summary: str):
        """Extract severity information from a summary."""
        return self.severity_parser.get_severity(summary)

    def get_cwe_from_summary(self, summary: str):
        """Extract CWE identifiers from a summary."""
        return self.cwe_parser.get_cwes(summary)
