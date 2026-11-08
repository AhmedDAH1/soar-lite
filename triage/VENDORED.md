# Bundled: ai-alert-triage v0.2.3

This folder is the triage engine from
[ai-alert-triage](https://github.com/AhmedDAH1/ai-alert-triage), release
[v0.2.3](https://github.com/AhmedDAH1/ai-alert-triage/releases/tag/v0.2.3),
copied unchanged (MIT, same author). Only the modules SOAR-Lite uses are
included; the evaluation, injection suite and CLI stay in that repository.

It is bundled rather than installed from GitHub so that building SOAR-Lite
never depends on downloading from GitHub, which timed out on Render and is
unreliable from some networks. `tests/test_vendored_triage.py` checks the
version. To update: copy the same files from a newer release, change the
version in that test, and run the tests.
