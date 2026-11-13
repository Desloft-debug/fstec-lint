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
