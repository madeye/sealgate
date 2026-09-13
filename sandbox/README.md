# Sandbox runtime

This directory holds the Linux Docker runtime and the macOS Seatbelt profile.
The macOS profile (`profile.sb`) is described in [macos.md](macos.md).

## Linux

`sealgate sandbox-build` builds `sealgate-sandbox:0.4.0` from this directory. The build
context contains only `Dockerfile` and the compiled `scripts/relay.ts` and
`scripts/firewall.ts` runtimes,
never workspace data or keys. Run the build through SEALGATE to assemble that context.
The base Node image is pinned by its multi-platform digest. Debian packages use
the distribution's signed repositories. Rebuild deliberately to receive updates.

The launcher creates two session containers. The relay has `--network=bridge`
and one read-only Unix socket directory mount. It forwards loopback port 17840
to the gateway socket and port 17841 to the optional proxy socket, which the
host creates only for `--proxy-egress`. The Claude container shares only
the relay's network namespace, with separate PID and mount namespaces. Its
seccomp policy permits Internet socket families with direct outbound access,
and denies filesystem/abstract Unix sockets. Anonymous socket pairs remain
available for local IPC. This prevents a mounted workspace socket from becoming
an escape to a host daemon. Both containers drop all capabilities, use an
unprivileged UID, enable no-new-privileges, and have read-only root filesystems.

Claude's `ANTHROPIC_BASE_URL` points to the loopback gateway relay. Tools can use
TCP and DNS directly without `--proxy-egress`; this traffic bypasses SEALGATE's
inspection and encryption. A temporary helper with `NET_ADMIN` installs nftables
rules in the shared network namespace before Claude starts. These reject every
protocol and port to the original provider's resolved IPv4/IPv6 addresses.
The helper has no workspace, credential, or gateway-socket mounts. Client and
relay retain no capabilities. The host pins the provider hostname in a read-only
hosts file and refreshes the firewall every 30 seconds, retaining old addresses;
refresh failure stops the client. Host gateway traffic is outside these rules.
The optional Linux tool proxy also rejects provider destinations.
Relay listeners bind only to loopback, with no
published Docker ports. The container's loopback remains separate from the host.

`seccomp.json` derives from the Moby default profile at commit
[`3c28324314729dbade8287e868eef6338c42807a`](https://github.com/moby/profiles/blob/3c28324314729dbade8287e868eef6338c42807a/seccomp/default.json).
It retains the default deny behavior and architecture-specific rules. SEALGATE removes
general `socket`, `socketcall`, ptrace, process-memory and io_uring allowances,
then permits `socket` only for AF_INET (2) and AF_INET6 (10).
Moby's profile is Apache-2.0 licensed; see [LICENSE.moby](LICENSE.moby).
The rest of SEALGATE is [MIT licensed](../LICENSE).

See [the gateway guide](../docs/gateway.md) for operational limits and verification.
