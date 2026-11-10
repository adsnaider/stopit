---
name: stopit-sandbox
description: >-
  Instructions for operating inside a `stopit` Linux sandbox: understanding
  masked (`.git`, `.jj`, `.env`) and protected (`.stopit.toml`, `flake.nix`)
  files, using brokered shims in `/run/stopit/bin` (`jj`, `git`), and requesting
  filesystem or network capabilities with `stopit-grant`. Use whenever hostname
  is `stopit`, `/run/stopit/bin` is on `PATH`, commands hit `Read-only file
  system` (`EROFS`) or empty `.git`/`.jj` directories, `[stopit: ...]` messages
  appear on stderr, or a command needs host paths or network access not in its
  profile.
---

# Operating Inside the `stopit` Sandbox

When running inside `stopit`, your process is isolated by Linux namespaces
(`bubblewrap`), Landlock, and a seccomp filter. Standalone runs (`stopit run`)
provide the supervisor and broker for rules with `decision = "allow"`, while an
attached `stopit server` session handles interactive approval prompts (`ask`)
and `stopit-grant` requests.

## 1. Detecting the Sandbox

You are inside a `stopit` sandbox if any of the following hold:
- `/run/stopit/bin` is at the front of `PATH` (or `/run/stopit` exists).
- `uname -n` / `hostname` returns `stopit`.
- Commands print `[stopit: ...]` diagnostics on stderr.

## 2. Filesystem Layout and Mount Modes

- **Workspace mount.** By default (`[workspace] mount = "/workspace"`), the
  project workspace is mounted at `/workspace`. When `[workspace] mount =
  "host"` is configured, the workspace is mounted at its canonical host path
  (e.g. `/home/<user>/repos/<project>`), matching paths in tool caches and build
  artifacts.
- **Ephemeral `~` and `/tmp`.** Your home directory (`~`) and `/tmp` are backed
  by session-scoped ephemeral directories on the host that persist across
  commands attached to the same `stopit server` and are deleted when the session
  ends. Host paths under `~` (such as `~/.ssh`) do not exist unless explicitly
  bound in (`~/.cargo`, `~/.rustup`, etc.).
- **Masked paths (`fs.masked`).** Sensitive files and directories inside the
  workspace (such as `.git`, `.jj`, `.env`, `.env.*`, `*.pem`, `*.key`,
  `.npmrc`, `.pypirc`, `.netrc`) are covered by 0-byte mode-`0000` files or
  empty read-only `tmpfs` directories. Opening or reading a masked file fails
  with `EACCES` (`Permission denied`), listing `.git` or `.jj` directly from
  `main` shows an empty directory, and writing to a masked path fails with
  `EROFS` (`Read-only file system`) or `EACCES`.
- **Protected paths (`fs.protected`).** Build and sandbox configuration files
  (such as `.stopit.toml`, `.envrc`, `flake.nix`, `flake.lock`,
  `.cargo/config.toml`, `.gitmodules`, `.claude`, `.gemini`, `.codex`,
  `opencode.json`, `.opencode`, and script or proxy shim sources) are mounted
  read-only (`EROFS` on write) so the sandbox cannot silently modify code or
  policy that runs on the host.

## 3. Brokered Shims (`/run/stopit/bin`)

Tools in `/run/stopit/bin` (such as `jj`, `git`, and custom shims) are
trampolines that forward your invocation over `/run/stopit/broker.sock` to the
host broker. The broker evaluates the shim's rules and runs the command in its
target profile (for example, `vcs.local`, where `.jj` and `.git` are unmasked).

- **Always use `PATH` for brokered tools.** Run `jj` and `git` by name so
  `/run/stopit/bin/jj` and `/run/stopit/bin/git` are used. Never invoke
  `/usr/bin/git` or `/nix/store/.../bin/jj` by full path from `main`, because
  `.git` and `.jj` are masked inside `main`.
- **Work inside the workspace.** Every shim call requires its current working
  directory to lie inside the workspace mount (`shims run only from inside the
  workspace`).
- **Approval prompts and exit code `126`.** When a shim rule has `decision =
  "ask"`, the broker prompts the user on the `stopit server` terminal (`[y]
  allow once  [s] allow for this session  [p] allow and persist  [n] deny`), or
  denies immediately in a standalone run without a server. If the broker refuses
  a command, the user denies it, or `[approval] timeout` expires before an
  answer (`approval prompt timed out after ...`), the shim prints `[stopit:
  <shim>: <reason>]` to stderr and exits with status `126`. Do not retry a
  denied command in a tight loop; adjust your approach or ask the user.
- **Default `vcs` shim rules (`stopit default-config`).**
  - Allowed without prompting (`allow`): `jj status`/`st`, `diff`, `log`,
    `show`, `evolog`, `op log`, `file show`, `new`, `commit`/`ci`,
    `describe`/`desc`; `git status`, `diff`, `log`, `show`, `add`, `commit`.
  - Denied outright (`deny`, exit `126`): config-injection, repository-override,
    and history-insertion flags (`jj --config*`, `-R`/`--repository`, `--tool`,
    `-i`/`--interactive`, `-A`/`--after`/`--insert-after`,
    `-B`/`--before`/`--insert-before`; `git -c`, `-C`, `--config-env`,
    `--exec-path`, `--upload-pack`, `--receive-pack`, `--exec`, `--output`,
    `--git-dir`, `--work-tree`, `--namespace`, and `clone -u`/`--template`).
  - Prompt by default (`ask`): history-rewriting or ref-moving commands (`jj
    squash`, `rebase`, `abandon`, `restore`, `undo`, `bookmark *`, `op *`; `git
    reset`, `rebase`, `checkout`, `switch`, `branch`, `tag`, `clean`, `stash`),
    remote commands (`jj git fetch`, `git clone`, `git push`; `git fetch`,
    `pull`, `ls-remote`, `remote update`, `clone`, `push`, which run in
    `vcs.remote` with network access and the host's `SSH_AUTH_SOCK` and
    `~/.ssh/known_hosts`), and any unlisted subcommand or invocation with flags
    before the subcommand.

## 4. Requesting Capabilities with `stopit-grant`

When a command needs temporary read-only or read-write access to a host path, or
network access not granted to your current profile, use `/run/stopit/bin/stopit-grant`:

```sh
stopit-grant [--scope '<program> [<words>]'] <grant>... -- <command> [args...]
```

### Supported `<grant>` Arguments (1 to 16 per call)

- **`+ro:<path>`.** Mount an existing host file or directory read-only at the
  same path (accepts an absolute path `/...` or `~/...`).
- **`+rw:<path>`.** Mount an existing host file or directory read-write at the
  same path (accepts an absolute path `/...` or `~/...`). Protected sources,
  masked paths, and read-only/ephemeral carvings inside an `rw` mount remain
  restricted and cannot be lifted by `stopit-grant`.
- **`+net:<domain>`.** Allow HTTP/HTTPS/SOCKS5 traffic to `<domain>` through
  `stopit`'s network proxy (`<domain>` must be an exact lowercase DNS hostname;
  wildcards such as `*.example.com` are not supported, so list each subdomain
  explicitly).
- **`+net:full`.** Request full network access via `pasta`.

### Using `--scope` for Session Reuse

By default, answering `[s] allow for this session` on a `stopit-grant` prompt
remembers the approval for `<program>` and the leading subcommand words before
the first `-` flag, paired with the exact set of grants. You can pass `--scope
'<program> [<words>]'` to specify `<program>` followed by single-space-separated
subcommand words matching `[a-z0-9][a-z0-9_-]*` (with an optional trailing `*`
wildcard after at least one subcommand word, such as `cargo sub *`), matching
the start of `<command> [args...]` before any `-` flag:

```sh
stopit-grant --scope 'cargo test' +ro:/nix/store -- cargo test --lib
```

If the user answers `[p] allow and persist` on the `stopit server` terminal, the
grants are written into `.stopit.toml` under `[[provider]] name = "approvals-<profile>"`
(such as `approvals-main`) and the server reloads its configuration immediately.

### `stopit-grant` Rules and Pitfalls

1. `--` is mandatory before `<command>`.
2. `<command>` must be a bare program name resolved in the temporary profile's
   `PATH` (it cannot contain `/`). To run a shell pipeline, builtin (`cd`), or
   an absolute binary path, wrap it in `sh -c '...'`:
   ```sh
   stopit-grant +ro:~/data -- sh -c 'cat ~/data/input.txt'
   ```
3. Must be run from a working directory inside the workspace.
4. Paths inside your sandbox home directory (`$HOME`) must be written with `~/`
   (e.g. `+ro:~/data`), not as `/home/<user>/data`.
5. Requested host paths must already exist on the host, must not contain `..` or
   globs, and must not be Unix domain sockets.
