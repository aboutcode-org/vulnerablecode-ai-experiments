# vulnerablecode-ai-experiments

This repository contains experiments with AI-driven parsers for analyzing vulnerabilities, extracting package URLs (PURLs), and determining affected/fixed version ranges.

## Usage

All parsers can be accessed through the VulnerabilityAgent class, which provides a unified interface for extracting structured vulnerability data.

**Create an instance of the `VulnerabilityAgent`:**
    ```bash
    instance = VulnerabilityAgent()
    ```

## Parsing a PackageURL

**Get the Package URL (PURL) for the given summary:**
    ```bash
    purl = instance.get_purl_from_summary(summary) # Output: pkg:pypi/django-helpdesk
    ```
    Ensure the `summary` variable contains the relevant information to extract the PURL.

**Get the version ranges (affected and fixed versions) from the summary:**
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
## Configuration

To configure the model source, set the appropriate environment variables. You can choose between using a local LLM model or the OpenAI API.

### Local LLM Model Configuration:

If you want to use a local LLM model, set the `USE_LOCAL_LLM_MODEL` environment variable to `True`, and provide the necessary details for the local model:

1. Set the following environment variables:
    - `OLLAMA_MODEL_NAME="your_model_name"`
    - `OLLAMA_BASE_URL="http://your_local_model_url"`

### OpenAI API Configuration:

If you prefer to use OpenAI's API, simply set the `OPENAI_API_KEY` environment variable:

1. Set the following environment variable:
    - `OPENAI_API_KEY="your_openai_api_key"`
    - `OPENAI_MODEL_NAME="gpt-4o-mini"`
