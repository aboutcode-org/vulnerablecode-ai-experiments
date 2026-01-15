# tests/ab_test.py
from __future__ import annotations

import importlib
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any, Dict, List
 
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
TESTS_DIR = Path(__file__).resolve().parent
PROMPTS_DIR = ROOT / "prompts"

# constants we expect prompt modules to provide (agent imports these from prompts)
PROMPT_NAMES = [
    "PROMPT_CWE_FROM_SUMMARY",
    "PROMPT_PURL_FROM_CPE",
    "PROMPT_PURL_FROM_SUMMARY",
    "PROMPT_SEVERITY_FROM_SUMMARY",
    "PROMPT_VERSION_FROM_SUMMARY",
]


def load_data_loader_module() -> Any:
    """Load tests/data_loader.py as a module (avoids package import issues)."""
    loader_path = TESTS_DIR / "data_loader.py"
    spec = importlib.util.spec_from_file_location("tests.data_loader", str(loader_path))
    module = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(module)
    return module


def discover_prompt_modules() -> List[str]:
    """List prompt module names under prompts/ like prompt_v1, prompt_v2, ..."""
    mods: List[str] = []
    for p in PROMPTS_DIR.glob("prompt_v*.py"):
        name = p.stem  # e.g., prompt_v1
        mods.append(name)
    # ensure deterministic ordering
    mods.sort()
    return mods


def import_prompt_module(mod_name: str):
    """Import prompts.<mod_name> and return the module."""
    full_name = f"prompts.{mod_name}"
    return importlib.import_module(full_name)


def inject_prompt_values(prompt_mod) -> None:
    """
    Copy prompt constants from prompt module into the prompts package module
    so `from prompts import ...` (used by agent) will get updated values on reload.
    """
    prompts_pkg = importlib.import_module("prompts")
    for pname in PROMPT_NAMES:
        if hasattr(prompt_mod, pname):
            setattr(prompts_pkg, pname, getattr(prompt_mod, pname))


def reload_agent_and_create_agent_instance():
    """Reload agent module so it re-reads prompt constants; return VulnerabilityAgent class instance."""
    agent_mod = importlib.import_module("agent")
    importlib.reload(agent_mod)
    return agent_mod.VulnerabilityAgent()


def evaluate_on_dataset(agent_instance, dataset: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Run agent on dataset and collect simple metrics."""
    total = 0
    severity_correct = 0
    cwe_correct = 0
    errors: List[Dict[str, Any]] = []

    for item in dataset:
        total += 1
        summary = item.get("summary", "")
        expected_severity = item.get("expected_severity")
        expected_cwe_list = item.get("expected_cwe_list", [])

        try:
            pred_sev = agent_instance.get_severity_from_summary(summary)
            pred_cwes = agent_instance.get_cwe_from_summary(summary)

            # normalize to lower-case for severity comparison
            if pred_sev is not None and str(pred_sev).lower() == str(expected_severity).lower():
                severity_correct += 1

            # CWE: compare canonical sets "CWE-79" style -> normalize as set
            expected_set = {str(c).strip().upper() for c in expected_cwe_list}
            pred_set = {str(c).strip().upper() for c in (pred_cwes or [])}

            if expected_set == pred_set:
                cwe_correct += 1

        except Exception as e:
            errors.append(
                {"summary_preview": summary[:200], "error": repr(e), "expected_severity": expected_severity}
            )

    return {
        "total": total,
        "severity_correct": severity_correct,
        "cwe_correct": cwe_correct,
        "severity_accuracy": (severity_correct / total) if total else 0.0,
        "cwe_accuracy": (cwe_correct / total) if total else 0.0,
        "errors": errors,
    }

def write_results_to_file(results: Dict[str, Any]) -> None:
    """Persist A/B test results to a JSON file."""
    output_path = TESTS_DIR / "ab_results.json"
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)


def main():
    # 1) load dataset via tests/data_loader.py
    data_loader = load_data_loader_module()
    dataset = data_loader.load_dataset()

    # 2) discover prompt modules
    prompt_mod_names = discover_prompt_modules()
    if not prompt_mod_names:
        print("No prompt_v*.py found in prompts/ — nothing to run.")
        return

    results = {}
    for mod_name in prompt_mod_names:
        print(f"\n=== Running A/B candidate: {mod_name} ===")
        prompt_mod = import_prompt_module(mod_name)

        # inject prompt values into prompts package so agent reload picks them up
        inject_prompt_values(prompt_mod)

        # reload agent so it binds to the new prompt constants, then create instance
        agent_inst = reload_agent_and_create_agent_instance()

        # evaluate
        metrics = evaluate_on_dataset(agent_inst, dataset)
        results[mod_name] = metrics

        # basic printout
        print(
            f"{mod_name}: {metrics['total']} samples, "
            f"severity acc: {metrics['severity_accuracy']:.3f}, "
            f"CWE acc: {metrics['cwe_accuracy']:.3f}, "
            f"errors: {len(metrics['errors'])}"
        )

    print("\n=== Full results ===")
    print(json.dumps(results, indent=2))
    
    write_results_to_file(results)
    print(f"\nResults written to {TESTS_DIR / 'ab_results.json'}")


if __name__ == "__main__":
    main()
