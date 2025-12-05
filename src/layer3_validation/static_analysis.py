import re

class StaticAnalyzer:
    """
    Layer 3A: Static analysis for harmful constructs.
    """

    def __init__(self):
        self.forbidden = [
            r"os\.system\s*\(",
            r"subprocess\.Popen",
            r"eval\s*\(",
            r"exec\s*\(",
            r"__import__",
            r"rm -rf",
        ]

    def analyze(self, code):
        issues = []

        for pattern in self.forbidden:
            if re.search(pattern, code, flags=re.IGNORECASE):
                issues.append(f"Dangerous pattern detected: {pattern}")

        return {
            "safe": len(issues) == 0,
            "issues": issues
        }
