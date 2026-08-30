# tp, terminal paste

Share a paste with the machine next to you. No server, no account, no internet.

```
$ tp post notes.txt
otter-piano-cobalt

$ tp get otter-piano-cobalt      # on the other machine
```

The paste lives in the sender's process memory and is served straight to the
fetcher over TLS. Process exit or reboot destroys everything.

## Install

```
curl -fsSL https://raw.githubusercontent.com/shaiq-dev/tp/main/install.sh | sh
```

The script verifies a signed release manifest before it unpacks anything, so it
needs [minisign](https://jedisct1.github.io/minisign/) (`brew install minisign`,
`apt install minisign`, `dnf install minisign`, `apk add minisign`). It installs
to `~/.local/bin/tp`, never uses `sudo`, and does not touch your shell rc files.

Pick a version or a location with `TP_VERSION=v0.1.0` and `TP_PREFIX=/opt/tp`.

Or skip the script:

```
go install github.com/shaiq-dev/tp@latest          # needs Go 1.26.6+
make install                                        # from a checkout
```

Prebuilt tarballs and a `SHA256SUMS` file are attached to every
[release](https://github.com/shaiq-dev/tp/releases).

## Supported platforms

| OS | Architectures |
|---|---|
| macOS 12 Monterey and later | `amd64`, `arm64` |
| Linux, kernel 3.2 and later | `amd64`, `arm64`, `armv7`, `386` |

Binaries are built with `CGO_ENABLED=0`, so they are static and do not depend on
glibc, musl or any distro version. Both machines need to be on the same network,
not on the same OS.

## Building

```
make build     # ./tp for this machine
make test      # go test -race
make check     # everything CI runs
make lint      # golangci-lint on its own
make dist      # every platform, tarballs, checksums and manifest into dist/
```

Nothing beyond Go and a POSIX shell is required, and `make help` lists the rest.
Cross building lives in `scripts/` and runs without make, so
`VERSION=v0.1.0 scripts/build.sh` does the same thing as `make dist`.

## Commands

```
tp post [file]     read stdin or file, return a code
tp get <code>      fetch a paste to stdout
tp list            list pastes this machine is serving
tp del <code>      stop serving a paste
```

`tp post` takes `--label`, `--ttl`, `--max-gets`, `--burn` and
`--code-style=digits`. `tp get` takes `--host` to skip discovery.

Codes accept unambiguous abbreviations: `tp get otte-pian-coba` works.

## How the code stays safe

The code is short enough to say across a desk, which caps it at about 31 bits.
That is far too little to send over a hostile network, so it is never sent, in
any form. Both sides run a balanced PAKE (CPace over ristretto255) with the code
as the password, bound to the TLS channel. A hostile node on your wifi gets one
guess per connection, rate limited to 20 a minute, and learns nothing it can
attack offline.

## Things that are expected, not bugs

- **A suspended laptop stops serving.** The paste is in memory on the sender.
  Nothing to fix; wake it up.
- **Guest, hotel and enterprise wifi usually block client-to-client traffic**
  and drop multicast. `tp` cannot work there. It detects this at startup and
  says so rather than failing silently.
- **macOS 15+ prompts for Local Network access** on the first multicast send.
  The prompt is attributed to your terminal app, not to `tp`. If discovery finds
  nothing, check System Settings, Privacy and Security, Local Network.
- **The macOS firewall may prompt** on the first inbound connection.

## License

[MIT](LICENSE).
