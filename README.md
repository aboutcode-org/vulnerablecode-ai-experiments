# vulnerablecode-ai-experiments

This repository contains experiments with AI-driven parsers for analyzing vulnerabilities, extracting package URLs (PURLs), and determining affected/fixed version ranges.

## Usage

All parsers can be accessed through the `VulnerabilityAgent` class, which provides a unified interface for extracting structured vulnerability data.

**Create an instance of the `VulnerabilityAgent`:**
    ```bash
    instance = VulnerabilityAgent()
    ```

## Parsing a PackageURL

**Get the Package URL (PURL) from a summary**
    ```bash
    purl = instance.get_purl_from_summary(summary) # Output: pkg:pypi/django-helpdesk
    ```
    Ensure that the summary variable contains enough information to extract the PURL.

**Get affected and fixed version ranges**
    ```bash
    version_ranges = instance.get_version_ranges(summary, purl.type)
    ```
    This will return a tuple containing two lists:
    - `affected_versions`: Versions affected by the vulnerability
    - `fixed_versions`: Versions where the vulnerability has been fixed

    Example output:
    ```bash
    print(version_ranges)  # Output: ([affected_version_range], [fixed_version_range]])
    ```

## Parsing a CPE

**Get the Package URL (PURL) for the given cpe:**
    ```bash
    cpe = "cpe:2.3:a:django-helpdesk_project:django-helpdesk:-:*:*:*:*:*:*:*"
    pkg_type = "pypi"
    purl = instance.get_purl_from_cpe(cpe, pkg_type)
    print(purl)  # Output: pkg:pypi/django-helpdesk
    ```
    Ensure the `cpe` variable contains the relevant information to extract the PURL.

## Parsing a Vulnerability

**Get the Severity for the given summary:**
    ```bash
    summary = "..."
    severity = instance.get_severity_from_summary(summary)
    print(severity)  # low , medium, high , critical 
    ```
    Ensure the `cpe` variable contains the relevant information to extract the PURL.

**Get the CWE for the given summary:**
    ```bash
    summary = "Deserialization of untrusted data in Microsoft Office SharePoint allows an authorized attacker to execute code over a network."
    cwes = instance.get_cwe_from_summary(summary)
    print(cwes)  # Output: CWE-502
    ```
    Ensure the `cpe` variable contains the relevant information to extract the PURL.
 
---

### LLM Configuration:

To setup your LLM model, configure the following environment variables:
```
OPENAI_API_KEY="your-open-ai-api-key"
OPENAI_API_BASE="your-open-ai-api-base"
OPENAI_MODEL_NAME="your-open-ai-api-model-name"
OPENAI_TEMPERATURE=your-model-temperature # must be a float value between 0 and 1

# optionally, you can also set a seed to produce more reproducable outputs
OPENAI_MODEL_SEED=1223372036854775807
```

> **NOTE**: The following variables can be configured with the credentials of any OpenAI compatible API (OpenAI, Ollama, lm-studio, openrouter, etc).

The above values can either be set in your environment variables, or in a `.env` file at the root of this project. To create a `.env` file, simply clone the `.env.sample` file and update the values.