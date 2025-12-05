import ast
import difflib
import re

from .static_analysis import StaticAnalyzer
from .diff_checker import DiffChecker
from .semgrep_runner import SemgrepRunner
from .unit_test_validator import UnitTestValidator


class PatchValidator:
    """
    Layer 3: Output Validation
    - Static analysis
    - Diff minimality check
    - Syntax validation (AST parsing)
    """

    def __init__(self):
        self.static_analyzer = StaticAnalyzer()
        self.diff_checker = DiffChecker()
        self.semgrep = SemgrepRunner()
        self.unit_tester = UnitTestValidator()

    # -----------------------------------------------------------
    #  AST SYNTAX CHECKER
    # -----------------------------------------------------------
    def syntax_is_valid(self, code: str) -> bool:
        """
        Returns True if the patch code is syntactically valid Python.
        Uses the built-in AST parser.
        """
        try:
            ast.parse(code)
            return True
        except SyntaxError:
            return False

    # -----------------------------------------------------------
    #  MASTER VALIDATION PIPELINE
    # -----------------------------------------------------------
    def validate(self, original_code: str, generated_patch: str) -> dict:
        """
        Runs all three validators:
        1. static analysis
        2. diff validation
        3. syntax validation
        """

        static_result = self.static_analyzer.analyze(generated_patch)
        diff_result = self.diff_checker.compare(original_code, generated_patch)
        syntax_valid = self.syntax_is_valid(generated_patch)
        semgrep_result = self.semgrep.run(generated_patch)

        # optional: keep empty tests if no tests provided
        test_code = (
            "import patched\n"
            "def test_add():\n"
            "    assert patched.add(1, 2) == 3\n"
        )


        unit_test_result = self.unit_tester.run_tests(generated_patch, test_code)

        overall_valid = (
            static_result["safe"]
            and diff_result["valid"]
            and syntax_valid
            and semgrep_result["safe"]
            and unit_test_result["passed"]
        )

        return {
            "valid": overall_valid,
            "static_analysis": static_result,
            "diff_analysis": diff_result,
            "syntax_valid": syntax_valid,
            "semgrep": semgrep_result,
            "unit_tests": unit_test_result
        }


# -----------------------------------------------------------
# Manual test
# -----------------------------------------------------------
if __name__ == "__main__":
    validator = PatchValidator()

    original = """
def add(a, b):
    return a + b
"""

    patched = """
def add(a, b):
    return a + b + 1
"""

    print("=== Validation Output ===")
    print(validator.validate(original, patched))
