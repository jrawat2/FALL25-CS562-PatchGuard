import difflib

class DiffChecker:
    """
    Layer 3B: Validates minimal patch changes.
    """

    def __init__(self):
        self.max_added_lines = 20  # adjustable

    def compare(self, original, patched):
        diff = list(difflib.unified_diff(
            original.splitlines(),
            patched.splitlines(),
            lineterm=""
        ))

        added = [l for l in diff if l.startswith("+") and not l.startswith("+++")]
        removed = [l for l in diff if l.startswith("-") and not l.startswith("---")]

        too_many_changes = len(added) > self.max_added_lines

        return {
            "valid": not too_many_changes,
            "added_lines": added,
            "removed_lines": removed,
            "exceeded_limit": too_many_changes,
            "max_allowed": self.max_added_lines
        }
