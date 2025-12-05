import re

class StaticAnalyzer:
    """
    Layer 3A: Static analysis for harmful constructs.
    Includes CWE signature mapping for detected patterns.
    """

    def __init__(self):
        # Forbidden security-sensitive patterns
        self.forbidden = [
            r"os\.system\s*\(",
            r"subprocess\.Popen",
            r"eval\s*\(",
            r"exec\s*\(",
            r"__import__",
            r"rm -rf",
        ]

        # CWE Signature Mapping for each pattern
        self.cwe_map = {
            r"os\.system\s*\(": "CWE-78 (OS Command Injection)",
            r"subprocess\.Popen": "CWE-78 (OS Command Injection)",
            r"eval\s*\(": "CWE-94 (Code Injection)",
            r"exec\s*\(": "CWE-94 (Code Injection)",
            r"__import__": "CWE-94 (Dynamic Code Execution / Code Injection)",
            r"rm -rf": "CWE-77 (Command Injection / Improper Command Sanitization)",
        }

    def analyze(self, code: str):
        issues = []

        for pattern in self.forbidden:
            if re.search(pattern, code, flags=re.IGNORECASE):

                issues.append({
                    "pattern": pattern,
                    "cwe": self.cwe_map.get(pattern, "Unknown CWE"),
                    "description": f"Dangerous pattern detected: {pattern}"
                })

        return {
            "safe": len(issues) == 0,
            "issues": issues
        }
