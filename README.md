# vulnerablecode-ai-experiments

This repository contains experiments with the AI-driven summary parser for analyzing vulnerable code.

## Usage

To use the `VulnerabilitySummaryParser`, follow these steps:

1. **Create an instance of the `VulnerabilitySummaryParser`:**

    ```bash
    instance = VulnerabilitySummaryParser()
    ```

2. **Get the Package URL (PURL) for the given summary:**

    ```bash
    purl = instance.get_purl(summary)
    ```

    Ensure the `summary` variable contains the relevant information to extract the PURL.

3. **Get the version ranges (affected and fixed versions) from the summary:**

    ```bash
    version_ranges = instance.get_version_ranges(summary, purl.type)
    ```

    This will return a tuple containing two lists:
    - `affected_versions`: Versions affected by the vulnerability.
    - `fixed_versions`: Versions where the vulnerability has been fixed.

    Example output:

    ```bash
    print(version_ranges)  # Output: ([affected_versions], [fixed_versions])
    ```

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
