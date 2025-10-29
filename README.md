# vulnerablecode-ai-experiments

This repository contains experiments with AI-driven parsers for analyzing vulnerabilities, extracting package URLs (PURLs), and determining affected/fixed version ranges.

## Usage

You can interact with all parsers through the VulnerabilityAgent class, which provides a single entry point for:

1. **Create an instance of the `VulnerabilityAgent`:**
    ```bash
    instance = VulnerabilityAgent()
    ```

2. **Get the Package URL (PURL) for the given summary:**
    ```bash
    purl = instance.get_purl_from_summary(summary) # Output: pkg:pypi/django-helpdesk
    ```
    Ensure the `summary` variable contains the relevant information to extract the PURL.

3. **Get the version ranges (affected and fixed versions) from the summary:**
    ```bash
    version_ranges = instance.get_version_ranges(summary, purl.type)
    ```
    This will return a tuple containing two lists:
    - `affected_versions`: Versions affected by the vulnerability
    - `fixed_versions`: Versions where the vulnerability has been fixed

    Example output:
    ```bash
    print(version_ranges)  # Output: ([affected_versions], [fixed_versions])
    ```

## Parsing a CPE

1. Create an instance of the VulnerabilityAgent:
    ```bash
    instance = VulnerabilityAgent()
    ```

2. **Get the Package URL (PURL) for the given cpe:**
    ```bash
    cpe = "cpe:2.3:a:django-helpdesk_project:django-helpdesk:-:*:*:*:*:*:*:*"
    pkg_type = "pypi"
    purl = instance.get_purl_from_cpe(cpe, pkg_type)
    print(purl)  # Output: pkg:pypi/django-helpdesk
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