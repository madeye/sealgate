# macOS sandbox profile

`sealgate claude` on macOS confines the native Claude binary and every process it
starts with `/usr/bin/sandbox-exec -f profile.sb`. The profile in this directory is
a static template: host paths and ports are supplied as `-D` parameters and
referenced with `(param "NAME")`, so no host data is ever interpolated into
sandbox policy text. The launcher inserts only rules that reference parameters
or validated port numbers at the `@@EXTRA_RULES@@` marker.

## Shape

- `(deny default)`, then an allowlist for process, pseudo-terminal, shared
  memory, sysctl and device operations. The allowlist follows the profile used
  by Claude Code's own sandbox runtime, which is exercised daily against real
  developer tools. Two changes: `kern.procargs` sysctl reads are denied so other
  processes' arguments stay hidden, and the Keychain (`SecurityServer`,
  `securityd`) and LaunchServices (`launchservicesd`) Mach services are removed.
- Network: only `(allow network-outbound (remote ip "localhost:<gateway port>"))`,
  plus the proxy forwarder port when `--proxy-egress` is set. Everything else,
  including DNS via mDNSResponder, Unix sockets, UDP, Network.framework clients
  and listening sockets, is denied.
- Files: system trees are readable. `/Users`, `/Volumes` and the per-user
  `/private/var/folders` tree are denied, then the project, the per-launch
  runtime directory, the Claude binary, `/private/tmp` and the configured
  `sandboxReadPaths` are re-allowed. Writes are limited to the project, the
  runtime directory, `/private/tmp` and terminal or pipe devices. The key
  directory and the project's `.env` are denied for both reads and writes so
  `ln`, `mv` and `cp -c` cannot lift them.
- Deliberately absent: `lsopen` and LaunchServices (`open`), `appleevent-send`
  (`osascript`), `job-creation` and `mach-register` (`launchctl`), the pasteboard,
  Spotlight, `nsurlsessiond` and DNS services. Setuid programs such as `ps`,
  `top` and `sudo` cannot be executed under any Seatbelt profile.

## Verified on macOS 26

Under this profile the real Claude binary runs, reads the copied credentials
file after its Keychain lookup is denied, and completes tool calls. Probes for
external TCP, other loopback ports, DNS, workspace Unix sockets, `listen()`,
`open`, `osascript`, `launchctl submit`, `pbpaste`, `security
find-generic-password`, home-directory reads and writes outside the allowed
trees all fail, while `child_process.fork` IPC, `/dev/stdout` redirection and
`realpath` keep working. The gated suite `npm run test:seatbelt` repeats these
checks. Watch live denials with:

```sh
/usr/bin/log stream --style compact --predicate 'sender == "Sandbox"'
```

## Limits

Seatbelt shares the host kernel and Mach IPC namespace; Docker on Linux is the
stronger boundary. Apple has deprecated `sandbox-exec` while continuing to ship
and use it; if it disappears, the launcher refuses to run Claude unconfined.
Nested profiles are refused, so Claude Code's built-in Bash sandbox does not
work inside SEALGATE. The `/dev/ttys*` write allowance needed for child
pseudo-terminals also covers your other terminals.

## Session cleanup

A Node supervisor runs inside the same Seatbelt instance as Claude. On normal
client exit or cancellation, the host enumerates live user PIDs without reading
arguments or environments and sends them over a private IPC channel. The
supervisor stops and kills only processes the kernel permits it to signal via
`(target same-sandbox)`. This catches detached, reparented and double-forked tools;
it does not depend on process groups or inherited environment markers. The host
repeats enumeration until a sweep finds no remaining session processes, then
removes the temporary runtime. Other sandbox sessions and host processes are
outside that signal permission. The helper refuses to start without host IPC or
if it can signal its host parent.
The kernel's signal path applies permission checks to each target; see Apple's
[XNU signal implementation](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/kern_sig.c).

Cancellation gives the client 1.5 seconds to exit before forced cleanup. A forced
host/supervisor crash or SIGKILL can still prevent cleanup; an unexpected supervisor
exit is reported as an error, never successful session completion. This is lifecycle
supervision, not an additional security boundary against a hostile process that
can signal another member of its own sandbox.
