# Why watch mode behaves the way it does

Watch mode makes four choices that surprise people who expect a conventional
file watcher. Each one is deliberate, and knowing why prevents working around
behavior that is load-bearing.

For the commands themselves, see
[Watch policy tests while editing](../how-to/watch-policy-tests.md).

## It polls, rather than using filesystem events

A filesystem watch registered on a *file* does not survive that file being
replaced. Typed edits and essentially every competent editor save by writing a
temporary file and renaming it over the original, which means an inotify-style
watch on the policy path stops firing after the very first save — silently,
and in a way that looks like "my tests stopped re-running."

Polling re-resolves the path on every tick, so a rename is invisible to it. It
also adds no dependency, which matters for a binary that is meant to be
audit-clean.

The cost is a fixed interval of latency, defaulting to `500ms`. That is the
trade: bounded, predictable lag in exchange for a loop that cannot silently
stop working.

## A change is a content hash, not a modification time

Rewriting the file with identical bytes re-runs nothing. An mtime-based
watcher would re-grade on every save, including the many saves that change
nothing.

More importantly, a run happens only once the digest is **identical on two
consecutive polls**. That single mechanism does two jobs:

- It establishes a quiet period, so a burst of rapid saves produces one run
  rather than one run per save.
- It guards against grading a half-written file. A file caught mid-write
  hashes differently on the next poll, so it is never evaluated.

Deriving both from one rule is why there is no separate debounce setting to
tune, and no window in which a partial policy can produce a verdict.

## It never exits non-zero for a verdict

An exit code is a point-in-time judgment. A watch loop has no single point in
time.

If watch mode exited `1` on a red suite, that code would mean two different
things at once: "your assertions are failing" and "you happened to interrupt
while they were failing." A caller could not distinguish them, and neither
could a person.

So interrupt always exits `0`, whatever the last run reported. Use a
single-shot `test` when you need a verdict — that is what CI gates should
call.

Exit `2` is still reserved for the watcher's *own* failures: an unreadable
`--file`, a non-positive `--interval`, a flag combination that cannot apply,
or a write that fails and returns an error, such as a full disk.

A policy that cannot be parsed is deliberately none of those. It prints
nothing on stdout, logs once to stderr, and leaves the loop running — because
a policy is invalid for a moment during almost every edit, and a watcher that
died on the first malformed save would be useless.

## Closing its reader does not stop it

This one costs people real time, so it is worth stating precisely.

```sh
tail-acl test --watch | head -1   # does NOT return you to a prompt
```

A broken pipe is only detected by *writing* to it. A watcher that has already
graded the current file writes nothing until that file changes. So `head`
exits, the pipe breaks, and the watcher keeps polling — unaware, because it has
nothing to say yet.

The *next* save is what fails to write, and what happens then depends on the
platform:

| Platform | Mechanism | Exit |
| --- | --- | --- |
| Unix | Go runtime raises `SIGPIPE` on the failed write to fd 1; the default disposition kills the process before watch mode's own error handling runs | `141` |
| Windows | No `SIGPIPE`; the failed write surfaces as an ordinary error through the same path as a full disk | `2` |

Both are ordinary behavior for a streaming tool, not a bug. The practical rule
is simply: stop a watcher by interrupting it, not by closing its reader.

## Why `--validate` is opt-in

Plain `test --watch` is offline and deterministic. Making it consult the
control plane whenever credentials happened to be present would mean the same
command did different things on different machines, and would put network
access behind an environment variable rather than an explicit choice.

`--validate` is therefore a flag you pass, not a capability that activates
itself. Credentials in the environment never change what plain `test --watch`
does.

The same reasoning explains why API unavailability under `--validate` exits
`2` rather than `1`: the control plane failing to answer is a collection
failure, and reporting it as a policy verdict would claim knowledge the run
does not have. That is the same boundary described in
[Offline evaluation and safety](./offline-evaluation.md).
