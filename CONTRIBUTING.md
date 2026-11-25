# Contributing

Thank you for looking. Small fixes are welcome, and so are reports from a real machine.

You need: Python 3.9 or newer. No other packages.

1. Fork the repo and make a branch.
2. Change one thing.
3. Run the tests:

   ```
   python -m unittest discover -s tests -v
   ```

4. Open a pull request. Say what was wrong and how you checked the fix.

## Rules

- Any way to lose a file is a bug. Add a test to `tests/test_safety.py` that fails first.
- Standard library only, one file.
- A dry run must never change anything.

New here? Look for issues marked `good first issue`.
