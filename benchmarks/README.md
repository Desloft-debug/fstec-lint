# Benchmarks

`historical/` contains unmodified OLD reports and claims, not fresh candidate metrics.
Their source corpus revisions are pinned in `run.sh`. Do not compare another revision
or apply these numbers to restored families. Raw/disputed labels remain unchanged.

KICS reads fixtures as data. ComplianceAsCode runs external shell scenarios and requires
a disposable Linux Docker container with FSTEC_BENCHMARK_DISPOSABLE=1, no host config,
no production connection and no user directories mounted. The interlock is not a sandbox.
Never run those evaluators on the user's OS. No fresh execution results are included.
Review the image, corpus revision, isolation and required tools before invoking run.sh.
Fresh reports go to results/ and must record Python, tool/corpus versions and candidate manifest.
Zero denominators in metric_values produce JSON null; the console summary also says null.

Synthetic acceptance tests are separate from external benchmarks.

## Audited harness (schema 2)

CaC reports preserve each selected scenario, its raw source-label expectation,
render/setup/scan failures, synthetic fixture evidence and separate runtime outcome.
Failed preparation or incomplete scans are never counted as TN/FN. Linux Jinja uses
StrictUndefined. Shell setup uses `bash -e -o pipefail` and a 30-second process-group
 timeout; this is a deliberate adaptation and requires fresh runs, not reuse of old
results. A successful shell exit is NOT proof of all postconditions. Raw fixture
snapshots must be checked when an outcome is disputed.

The optional `pwquality` Python binding supplies a real libpwquality config oracle
for A002. Without that binding, runtime results are `not_available`, not inferred
from fstec-lint or labels. It does not execute PAM, measure authentication, or cover
PAM overrides. Conflicting policy/runtime labels remain visible, never silently
relabeled. A002 finding subparameter currently relies on existing diagnostic text;
a future structured subtype requires a separately versioned finding contract.

SSH records `sshd -T` independently of filename labels. It only evaluates the global
context, not all Match contexts. Oracle unavailability/timeouts and rejected configs
are separate. S004 Protocol is a static policy check whose runtime oracle may disagree.

KICS retains eligible rule-id agreement after corpus exclusions, explicitly labeled.
This is not the complete historical matrix: raw_expected_records and raw_findings
retain source evidence independently of exclusions.
The `evaluable` matrix excludes failed scans and C012 CPU/memory queries because
existing findings have no stable resource subtype. These queries are unscorable,
not successful detections. C015 is partial policy overlap. TP/FN/FP service/file
units and negative-file TN counts must not be combined into overall accuracy.

`manifest.py` records actual binary paths/versions, dependency versions, hashes of
candidate source and corpora, base configuration and a caller-declared image digest.
This is provenance evidence, not automatic pinning. Verify image digest externally.
Shell output is retained only up to 64 KiB; it is spooled to disposable-container disk.
Container-level disk/memory/CPU/PID limits and a wall-clock timeout remain required.
Do not run shell scenarios on the host or with host mounts, Docker socket, or privileged mode.

Version 9 follow-up: successful shell commands also receive process-group cleanup.
This cannot catch descendants that deliberately create a new session; the guard is
not per-scenario isolation. Tear down the disposable container after the run and use
external resource/time supervision. Corpus manifests now hash actual files (including
dirty and untracked input) and record git status as well as HEAD. These manifests
still do not attest to where input originally came from.

The harness input manifest excludes results/outputs/.corpora and Python caches:
output files, especially the manifest being written, are not source inputs. Corpus
inputs are recorded separately. Cases in one container can still share host-level
container state: process cleanup and per-case fixture trees do not provide separate
namespaces, mounts or authentication databases. Results must not be described as
fully isolated independent runtime cases without an external per-case runner.
