import subprocess
import json
import tempfile

class SemgrepRunner:
    """
    Layer 3C: Semgrep Static Scanner
    Runs Semgrep security rules on the generated patch.
    """

    def run(self, code: str):
        # Write patched code to a temporary file for Semgrep to scan
        with tempfile.NamedTemporaryFile(delete=False, suffix=".py") as tmp:
            tmp.write(code.encode())
            tmp_path = tmp.name

        try:
            # Run Semgrep with Python security ruleset
            result = subprocess.run(
                ["semgrep", "--config", "p/python", "--json", tmp_path],
                capture_output=True, text=True
            )

            output = json.loads(result.stdout or "{}")

            findings = output.get("results", [])

            return {
                "safe": len(findings) == 0,
                "findings": findings
            }

        except Exception as e:
            return {
                "safe": False,
                "error": str(e)
            }
