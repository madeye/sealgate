# Sandbox runtime

`sealgate sandbox-build` builds `sealgate-sandbox:0.4.0` from this directory. The build
context contains only `Dockerfile` and the compiled `scripts/relay.ts` runtime,
never workspace data or keys. Run the build through SEALGATE to assemble that context.
The base Node image is pinned by its multi-platform digest. Debian packages use
the distribution's signed repositories. Rebuild deliberately to receive updates.

The launcher creates two temporary containers. The relay has `--network=none`
and one read-only Unix socket directory mount. The Claude container shares only
the relay's network namespace, with separate PID and mount namespaces. Its
seccomp policy permits Internet socket families, which have no external routes,
and denies filesystem/abstract Unix sockets. Anonymous socket pairs remain
available for local IPC. This prevents a mounted workspace socket from becoming
an escape to a host daemon. Both containers drop all capabilities, use an
unprivileged UID, enable no-new-privileges, and have read-only root filesystems.

`seccomp.json` derives from the Moby default profile at commit
[`3c28324314729dbade8287e868eef6338c42807a`](https://github.com/moby/profiles/blob/3c28324314729dbade8287e868eef6338c42807a/seccomp/default.json).
It retains the default deny behavior and architecture-specific rules. SEALGATE removes
general `socket`, `socketcall`, ptrace, process-memory and io_uring allowances,
then permits `socket` only for AF_INET (2) and AF_INET6 (10).
Moby's profile is Apache-2.0 licensed; see [LICENSE.moby](LICENSE.moby).
The rest of SEALGATE is [MIT licensed](../LICENSE).

See [the gateway guide](../docs/gateway.md) for operational limits and verification.
