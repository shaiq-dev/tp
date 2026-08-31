# tp, terminal paste

Share a paste with another machine on the same network. No server, account, or internet connection required. The sender keeps the paste in memory and serves it directly to the receiving machine. Stopping the daemon or rebooting the sender destroys it.

```bash
tp post notes.txt  # echo "Terminal Paste" | tp post
otter-piano-cobalt

tp get otter-piano-cobalt      # on the other machine
```


## Install

```bash
curl -fsSL https://raw.githubusercontent.com/shaiq-dev/tp/main/install.sh | sh
```

<br />
The installer downloads the latest release archive to `~/.local/bin/tp`. It does not use sudo or modify shell startup files. Set `TP_VERSION` to install a specific release or `TP_PREFIX` to choose another location:

```bash
curl -fsSL https://raw.githubusercontent.com/shaiq-dev/tp/main/install.sh | TP_VERSION=v0.1.0 sh
curl -fsSL https://raw.githubusercontent.com/shaiq-dev/tp/main/install.sh | TP_PREFIX=/opt/tp sh
```

<br />
You can also install from source:

```go
go install github.com/shaiq-dev/tp@latest
```

<br />
Prebuilt tarballs and a `SHA256SUMS` file are attached to every [release](https://github.com/shaiq-dev/tp/releases).


## Supported platforms

| OS | Architectures |
|---|---|
| macOS 12 Monterey or later | `amd64`, `arm64` |
| Linux, kernel 3.2 or later | `amd64`, `arm64`, `armv7`, `386` |

Release builds use `CGO_ENABLED=0`. Linux binaries do not depend on glibc, musl, or a particular distribution.


## Usage

| Command | Description |
| --- | --- |
| `tp post [file]` | Read a file or standard input and print its code |
| `tp get <code>` | Fetch a paste and write it to standard output |
| `tp list` | List pastes served by this machine |
| `tp del <code>` | Stop serving a paste |
| `tp doctor` | Diagnose discovery and local network problems |
| `tp uninstall` | Remove tp and its local data |
| `tp completion <shell>` | Generate completion for Bash, Zsh, or Fish |
| `tp version` | Build and platform information |

Useful posting options:

```sh
tp post --label notes --ttl 30m notes.txt
tp post --burn secret.txt
tp post --max-gets 3 archive.tar.gz
tp post --code-style=digits notes.txt
```

Use `--host` when you know the sender's address and want to bypass discovery:

```sh
tp get --host 192.168.1.20 otter-piano-cobalt
```

Word codes accept any unambiguous prefix, so this works too:

```sh
tp get otte-pian-coba
```


## How it works and security

1. `tp post` generates a three word code with about 31 bits of entropy, then derives a PAKE secret using scrypt. Each derivation uses roughly 32 MiB of memory, and the code itself is not retained.
2. Machines advertise candidate addresses over mDNS. These records are untrusted, a spoofed peer still has to complete PAKE key confirmation.
3. The receiver connects over TLS 1.3 and runs CPace over ristretto255. The code is never sent, and a wrong code produces nothing useful for offline guessing.
4. The sender returns a padded, shuffled set of confirmations because it cannot tell which stored paste the code identifies. Padding hides the exact number of live pastes.
5. After mutual confirmation, the payload is encrypted with a key derived from the PAKE session, in addition to TLS. Successful peers are pinned so later key changes are not silently accepted.

Each source address is limited to 20 connection attempts per minute. A global bucket limits testable guesses to 10 per second even when source addresses are rotated.

Pastes and derived PAKE secrets remain in the daemon's memory. Anyone who can read that process should be considered to have access to them, tp protects the network transfer, not a compromised endpoint.


## Discovery

Discovery uses IPv4 multicast and expects both machines to be on the same LAN. If no peer appears, run `tp doctor` or `tp doctor --listen 10s`.

Common blockers:

- **Guest, hotel, and enterprise Wi-Fi** often isolate clients or block multicast.
- **macOS 15 or later** requires Local Network permission for tp's signing identity. Run `tp doctor --fix`, or enable tp under **System Settings > Privacy & Security > Local Network**.
- **WSL2 NAT mode** does not pass multicast to the LAN. Set `networkingMode=mirrored` under `[wsl2]` in `%UserProfile%\.wslconfig`, then run `wsl --shutdown`.

## Daemon lifecycle

The CLI starts the daemon automatically when its control socket is absent. The daemon stops after its store is empty and it has been idle for 30 minutes.

An optional systemd user service is included in `contrib/tp.service` for users who prefer systemd to manage the daemon.

## Uninstall

```sh
tp uninstall
```
On macOS, the Local Network entry remains visible in System Settings but is inert after the binary is removed.


## Building

```sh
make build     # Build ./tp for this machine
make test      # Run tests with the race detector
make lint      # Run golangci-lint
make check     # Run all CI checks
make dist      # Build release archives, checksums, and manifest
```

The build requires Go, a POSIX shell, and GNU Make 3.81 or later. Run `make help` for the complete target list.

Cross compilation and packaging can also run without Make:

```sh
VERSION=v0.1.0 scripts/build.sh
```

## License

[MIT](LICENSE)


