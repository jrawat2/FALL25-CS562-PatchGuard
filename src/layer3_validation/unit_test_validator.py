import subprocess
import tempfile
import os

class UnitTestValidator:
    """
    Layer 3D: Execute unit tests on the patched code
    to ensure functional correctness.
    """

    def run_tests(self, code: str, test_code: str):
        # Create a temporary directory for executing tests
        with tempfile.TemporaryDirectory() as tmpdir:
            code_file = os.path.join(tmpdir, "patched.py")
            test_file = os.path.join(tmpdir, "test_patched.py")

            # Write the patched code
            with open(code_file, "w") as f:
                f.write(code)

            # Write the tests
            with open(test_file, "w") as f:
                f.write(test_code)

            # Use pytest quietly (-q)
            try:
                result = subprocess.run(
                    ["pytest", "-q", tmpdir],
                    capture_output=True, text=True
                )
                passed = (result.returncode == 0)

                return {
                    "passed": passed,
                    "stdout": result.stdout,
                    "stderr": result.stderr
                }

            except Exception as e:
                return {
                    "passed": False,
                    "error": str(e)
                }
