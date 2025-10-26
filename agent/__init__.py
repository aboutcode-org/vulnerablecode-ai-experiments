#
# Copyright (c) nexB Inc. and others. All rights reserved.
# VulnerableCode.ai is a trademark of nexB Inc.
# SPDX-License-Identifier: Apache-2.0
# See http://www.apache.org/licenses/LICENSE-2.0 for the license text.
# See https://github.com/aboutcode-org/vulnerablecode for support or download.
# See https://aboutcode.org for more information about nexB OSS projects.
#

import os
from typing import List, Optional

from aboutcode.hashid import get_core_purl
from dotenv import load_dotenv
from packageurl import PackageURL
from pydantic import BaseModel
from pydantic.functional_validators import field_validator
from pydantic_ai import Agent
from pydantic_ai.models.openai import OpenAIChatModel, OpenAIChatModelSettings
from pydantic_ai.providers.openai import OpenAIProvider
from univers.version_range import RANGE_CLASS_BY_SCHEMES

from prompts import (
    PROMPT_PURL_FROM_CPE,
    PROMPT_PURL_FROM_SUMMARY,
    PROMPT_VERSION_FROM_SUMMARY,
)

load_dotenv()

OPENAI_API_BASE = os.getenv("OPENAI_API_BASE")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OPENAI_MODEL_NAME = os.getenv("OPENAI_MODEL_NAME")
OPENAI_TEMPERATURE = os.getenv("OPENAI_TEMPERATURE", 0.3)


class Purl(BaseModel):
    string: str

    @field_validator("string")
    def check_valid_purl(cls, v: str) -> str:
        try:
            PackageURL.from_string(v)
        except Exception as e:
            raise ValueError(f"Invalid PURL '{v}': {e}")
        return v


class Versions(BaseModel):
    affected_versions: List[str]
    fixed_versions: List[str]


class BaseParser:
    def __init__(self, system_prompt: str, output_type):
        self.model = self._init_model()
        self.agent = Agent(
            self.model,
            system_prompt=system_prompt,
            model_settings=OpenAIChatModelSettings(temperature=OPENAI_TEMPERATURE, seed=1223372036854775807),
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


class PurlFromCPEParser(BaseParser):
    def __init__(self):
        super().__init__(PROMPT_PURL_FROM_CPE, Purl)

    def get_purl(self, cpe: str, pkg_type) -> Optional[PackageURL]:
        result = self.run_agent(
            f"**Vulnerability Known Affected Software Configurations CPE:**\n{cpe}\n **Package Type:**\n{pkg_type}"
        )
        purl = PackageURL.from_string(result.output.string)
        return get_core_purl(purl)


class VulnerabilityAgent:
    """Facade for all vulnerability parsing tasks."""

    def __init__(self):
        self.purl_parser = PurlFromSummaryParser()
        self.versions_parser = VersionsFromSummaryParser()
        self.cpe_parser = PurlFromCPEParser()

    def get_purl_from_summary(self, summary: str):
        return self.purl_parser.get_purl(summary)

    def get_version_ranges(self, summary: str, ecosystem: str):
        return self.versions_parser.get_version_ranges(summary, ecosystem)

    def get_purl_from_cpe(self, cpe: str, purl_with_no_version: str):
        return self.cpe_parser.get_purl(cpe, purl_with_no_version)
