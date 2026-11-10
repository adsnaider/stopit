# stopit

stopit runs a program, such as an LLM coding agent, a shell or a build, in a Linux sandbox. The sandbox sees your project and little else. Your home directory, SSH keys, cloud credentials and tokens in the environment stay out of reach unless the configuration grants them.

It is a single Rust binary built on [bubblewrap](https://github.com/containers/bubblewrap), Landlock and seccomp. Agents with full-screen terminal interfaces (Claude Code, Gemini CLI, Codex, OpenCode) run in it through a terminal proxy that filters what they may send to your terminal. `git` and `jj` run through a broker that keeps the repository's metadata out of the agent's reach.

> **Status: usable, still young.** These work and are tested against real sandboxes: the sandbox itself, the configuration and its trust checks, the terminal proxy, `stopit server` with its prompts, live configuration reload and saved approvals, the `full` and `proxy` network modes, brokered `git` and `jj` (including remote fetch and push via `vcs.remote` and `ssh-agent`), the `nix` development-shell provider, and resource limits. `stopit-grant` works for network and paths. Prompts for writes to protected files are not built yet. stopit has had no outside security review. [DESIGN.md](DESIGN.md) describes the design, and its section 11 lists the known gaps.

## Starting configuration (`stopit default-config`)

stopit bakes no implicit sandbox rules into its binary. Every profile, mount, environment filter, and shim comes from explicit TOML configuration in `~/.config/stopit/config.toml` and per-project `.stopit.toml`.

`stopit default-config` prints a ready-to-edit starting configuration for `~/.config/stopit/config.toml` that sets `default_profile = "main"`, declares `[profiles.main]`, and configures three providers (`base`, `protect-nix`, and `vcs`):

- your project, read-write, at `/workspace`, which is also the working directory;
- secrets in the project masked (`fs.warn_missing = false`): `.env`, `.env.*`, `*.pem`, `*.key`, `.npmrc`, `.pypirc`, `.netrc`, SSH keys and others show up empty and unreadable;
- files that exist when the session starts and would execute on the host made read-only: `.stopit.toml`, `.envrc`, `.vscode`, `.idea`, `.github/workflows`, `.claude`, `.gemini`, `.codex`, `opencode.json`, `.opencode`, `.cursor`, `.mcp.json`, `.zed`, and others in `base`, plus `*.nix` and `flake.lock` in `protect-nix` (DESIGN.md, Appendix A);
- the repository's `.git` and `.jj` masked when the workspace is a repository, with `git` and `jj` brokered through explicit `[provider.shims.*]` rules (see [Version control](#version-control));
- an empty home directory at `/home/stopit` and an empty `/tmp`, both deleted when the session ends;
- its own `/proc`, a minimal `/dev`, and `/var/run` linked to `/run`;
- generated `/etc/passwd`, `/etc/group`, `/etc/hosts` and `/etc/nsswitch.conf` naming the user `stopit` and the host `stopit`;
- loopback networking only, and `stopit-grant` enabled (`sandbox.grant = true`);
- an environment holding `HOME`, `USER`, `LOGNAME`, plus `TERM`, `LANG` and `COLORTERM` from yours. Variables matching `*_TOKEN`, `*_KEY`, `*_SECRET`, `*_PASSWORD`, `AWS_*`, `GITHUB_*`, `SSH_AUTH_SOCK` or `NIX_CONFIG` are never passed, in any letter case.

`/usr`, `/bin` and `/nix/store` are not mounted until you uncomment or add a `tools` (or `nix`) provider in `~/.config/stopit/config.toml`.

## Requirements

- Linux 5.13 or newer with unprivileged user namespaces enabled, and Landlock.
- bubblewrap 0.12 or newer on `PATH`.
- `$XDG_RUNTIME_DIR` set to a private directory, as systemd login sessions do.
- For `network = { mode = "full" }`: `pasta` from the passt package.
- For `[limits]`: a systemd user session, `busctl`, and cgroup v2.
- Rust 1.88 or newer to build.

## Install

```sh
cargo build --release      # the binary is target/release/stopit
```

With Nix, `nix build` gives a `stopit` that finds bubblewrap and pasta on its own, and `nix develop` a shell with the toolchain. The flake also has a Home Manager module (`programs.stopit.config` or `stopit.config`, which you can seed with `stopit default-config --format nix`):

```nix
imports = [ stopit.homeModules.default ];   # adds stopit to home.packages
```

## Quick start

1. Generate `~/.config/stopit/config.toml` from `stopit default-config` and grant your host tools for every project:

   ```sh
   mkdir -p ~/.config/stopit
   stopit default-config > ~/.config/stopit/config.toml
   ```

   Then uncomment one of the `tools` recipes at the bottom of `~/.config/stopit/config.toml` (or add your own). On Debian, Ubuntu, Fedora or Arch:

   ```toml
   [[provider]]
   name = "tools"
   type = "config"
   profile = "main"
   [provider.sandbox]
   fs.warn_missing = false
   fs.ro = [
     "/usr/bin", "/usr/sbin", "/usr/lib", "/usr/lib64", "/usr/libexec", "/usr/share",
     "/bin", "/lib", "/lib64", "/etc/alternatives", "/etc/ssl/certs", "/etc/pki",
   ]
   env.path_prepend = ["/usr/local/bin", "/usr/bin", "/bin"]
   ```

   On NixOS:

   ```toml
   [[provider]]
   name = "tools"
   type = "config"
   profile = "main"
   [provider.sandbox]
   fs.ro = ["/nix/store", "/run/current-system/sw", "/usr/bin/env", "/bin/sh", "/etc/ssl/certs"]
   env.path_prepend = ["/run/current-system/sw/bin"]
   ```

   `/usr/bin/env` and `/bin/sh` are there for scripts that start with `#!/usr/bin/env`. For packages from Home Manager, add your profile (`/etc/profiles/per-user/<you>`, or `~/.nix-profile`) to `fs.ro`, and its `bin` as the sandbox sees it (`/etc/profiles/per-user/<you>/bin` or `/home/stopit/.nix-profile/bin`) to `env.path_prepend`. Granting all of `/nix/store` is fine for trying stopit out. On NixOS the store can hold rendered secrets, so a careful setup grants only `/usr/bin/env`, `/bin/sh`, and `/etc/ssl/certs` globally and adds `[[provider]] name = "nix" type = "nix" profile = "main"` to mount each project's development shell closure (see [Use a Nix development shell](#use-a-nix-development-shell)).

   This file needs no `stopit allow`. stopit trusts it because only you can write it, and it checks that no sandbox can.

2. Initialize a project and run a command:

   ```sh
   cd ~/Projects/myproject
   stopit init                  # creates an empty .stopit.toml and allows it
   stopit run ls -la /workspace
   stopit shell                 # runs $SHELL, which must exist in the sandbox
   ```

   Every workspace requires an allowed `.stopit.toml` so it is mounted read-only in every sandbox. If the project already has a `.stopit.toml` (for example after cloning), review it and run `stopit allow` instead of `stopit init`. The command's exit code is passed through. stopit's own errors exit with 125.

3. To change what a project's sandboxes get, edit `.stopit.toml`:

   ```sh
   $EDITOR .stopit.toml
   ```

   stopit records `.stopit.toml`'s file identity (`dev`, `ino`, and creation time `btime`) rather than a content hash, so in-place edits take effect on the next run (or when pressing `r` in `stopit server`) without running `stopit allow` again. If `.stopit.toml` is deleted and recreated, or replaced by a tool or editor that writes a temporary file and renames it into place, run `stopit allow` once to trust the replacement file.

## Running agents

### The server

Start a server in the project in one terminal, and run the agent from another:

```sh
stopit server                         # terminal 1, stays in the foreground
stopit run --profile claude claude    # terminal 2
```

`stopit run` and `stopit shell` attach to the project's server when one runs, so every run shares one session, with one `/tmp` and one home. Questions for you, such as whether a brokered command may run or whether the agent may write to your clipboard, appear in the server's terminal, never in the agent's, so the agent cannot draw a fake prompt or answer one. On a prompt, `y` allows once, `s` allows for the session, `p` allows and saves the rule to `.stopit.toml` (updating `.stopit.toml` in place and reloading the server immediately), and `n` denies. Set `[approval] timeout = "5m"` (with `s`, `m`, or `h`, or `"off"` by default) in `config.toml` or `.stopit.toml` to auto-deny unanswered prompts after a deadline; `.stopit.toml` overrides `config.toml`. Without a server, anything that needs a yes is refused. `--standalone` runs without the server, and `--server ID` picks one by the id it prints. While no prompt is active, press `r` in the server's terminal to reload `config.toml` and `.stopit.toml` in place without losing the session's `/tmp` or home.

### Profiles for agents

A profile is a complete sandbox description. `default_profile` selects the profile used when `--profile` is omitted (`"main"` in `stopit default-config`). Omitting `inherit` on `[profiles.<name>]` starts from an empty sandbox, so set `inherit = "main"` to build an agent profile on top of `main`. Put an agent's profile in `~/.config/stopit/config.toml` next to the tools, so every project has it.

Each recipe below gives the agent a state directory of its own on the host, `~/.stopit-agents/<agent>`, which appears in the sandbox where the agent looks for its state. Do not grant the agent's usual directory (`~/.claude`, `~/.gemini`, `~/.codex`, `~/.config/opencode`) instead if you also run the agent outside stopit. The agent could rewrite its own settings there, such as hooks, MCP servers and plugins, which then run unsandboxed the next time you start it on the host, and it could read every past session you had with it. Create each directory first, since stopit skips a rule whose path is missing, with a warning. Then log in from inside the sandbox if the agent lets you paste a code. Copying the credentials file of a host login into the new directory works too, but a provider that rotates its refresh tokens can then log one of the two copies out. The agent can still change its settings in its own directory, and the change applies in every project where you run it in stopit. Login flows that open a browser and wait on a local port cannot reach a sandbox.

Each recipe lets the agent reach only the names it lists, plus any `main` allows, through stopit's filtering proxy. The proxy reaches them on ports 443 and 80 and lists the first ten names it refused when the run ends, in the server's terminal for an attached run. If an agent cannot log in or fetch something, add the names it needs, or use `network = { mode = "full" }`, which reaches whatever your machine reaches except services on its loopback. Anything the agent can read, it can send to the allowed names. The startup summary lists them on its `uploads` line. Node.js programs that do not read the proxy variables themselves need Node 24 or newer, where stopit's `NODE_USE_ENV_PROXY=1` takes effect.

The agent's program must be visible in the sandbox too. If you installed it through Nix or the system's packages, the tools provider covers it. If you installed it into your home, grant it there, as the Claude Code and Gemini recipes do.

**Claude Code**

```toml
[profiles.claude]
inherit = "main"

[[provider]]
name = "claude"
type = "config"
profile = "claude"
[provider.sandbox]
fs.bind = [{ host = "~/.stopit-agents/claude", sandbox = "/home/stopit/.claude", mode = "rw" }]
fs.ro = ["~/.local/bin/claude"]
env.path_prepend = ["/home/stopit/.local/bin"]
env.set = { CLAUDE_CONFIG_DIR = "/home/stopit/.claude", CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC = "1" }
network = { mode = "proxy", allow_domains = ["api.anthropic.com", "console.anthropic.com", "claude.ai"] }
```

`CLAUDE_CONFIG_DIR` keeps Claude Code's settings and login in that one directory rather than also in `~/.claude.json`, and the second variable turns off its telemetry. `~/.local/bin/claude` is where the native installer puts its launcher, a link to the current version, which the rule follows, so the sandbox gets that version's program itself. Drop both lines if Claude Code comes from Nix or the system. The project's `.claude` directory stays read-only, so the agent cannot change the project's settings, and "always allow" answers for the project fail to save.

**Gemini CLI**

```toml
[profiles.gemini]
inherit = "main"

[[provider]]
name = "gemini"
type = "config"
profile = "gemini"
[provider.sandbox]
fs.bind = [{ host = "~/.stopit-agents/gemini", sandbox = "/home/stopit/.gemini", mode = "rw" }]
fs.ro = ["~/.npm-global"]
env.path_prepend = ["/home/stopit/.npm-global/bin"]
network = { mode = "proxy", allow_domains = ["generativelanguage.googleapis.com", "cloudcode-pa.googleapis.com", "oauth2.googleapis.com"] }
```

`~/.npm-global` stands for wherever `npm install -g` put it. Turn off its usage statistics in the new directory's `settings.json`. Gemini CLI reads an API key from `GEMINI_API_KEY`, which the default filter drops (`*_KEY`). Prefer its login. If you set the key with `env.set` instead, which the filter does not touch, put it only in `~/.config/stopit/config.toml`, never in a `.stopit.toml` that goes into a repository, and keep that file mode 600. Every program in the profile, including the commands the agent runs, can read it.

**Codex**

```toml
[profiles.codex]
inherit = "main"

[[provider]]
name = "codex"
type = "config"
profile = "codex"
[provider.sandbox]
fs.bind = [{ host = "~/.stopit-agents/codex", sandbox = "/home/stopit/.codex", mode = "rw" }]
network = { mode = "proxy", allow_domains = ["api.openai.com", "chatgpt.com", "auth.openai.com"] }
```

Codex has a sandbox of its own. If Codex cannot start it inside stopit, `--sandbox danger-full-access` turns it off. stopit then still limits what Codex's commands can do, but Codex no longer keeps them out of `~/.codex` or off the network, so they can rewrite its configuration and reach the allowed names.

`stopit default-config` protects `.codex/` when it already exists at session start (`fs.warn_missing = false`). The agent can still create `.codex/` in a project that had none.

**OpenCode**

```toml
[profiles.opencode]
inherit = "main"

[[provider]]
name = "opencode"
type = "config"
profile = "opencode"
[provider.sandbox]
fs.bind = [
  { host = "~/.stopit-agents/opencode/config", sandbox = "/home/stopit/.config/opencode", mode = "rw" },
  { host = "~/.stopit-agents/opencode/data", sandbox = "/home/stopit/.local/share/opencode", mode = "rw" },
]
network = { mode = "proxy", allow_domains = ["models.dev", "registry.npmjs.org", "api.anthropic.com", "api.openai.com"] }
```

List the API of each model provider you use with it. `registry.npmjs.org` is there because OpenCode installs packages at run time, which it then runs, and the proxy lets it upload there too. Its cache stays in the session's home. `stopit default-config` protects existing `opencode.json` and `.opencode/` entries at session start, though the agent can still create them in a project that had none.

### What an agent sees

- **Your terminal, through a proxy.** stopit gives the sandbox a terminal of its own and copies its output to yours, dropping escape sequences that could change your terminal's settings or read them back. Colors, cursor movement, the alternate screen, window titles and mouse reporting pass. Writes to your clipboard (OSC 52) are blocked. With `[terminal] clipboard_write = "ask"`, each waits for your answer in the server's terminal (DESIGN.md section 5.3).
- **Version control** through the broker (next section).
- **Nothing of your home** beyond what a profile grants. The sandbox home is empty and shared by the session's runs.

An agent skill at `skills/stopit-sandbox/SKILL.md` teaches agents how the sandbox environment works, how brokered `git` and `jj` behave, and how to request extra paths or domains with `stopit-grant`. Copy or link it into the agent's skills directory inside its sandbox state directory.

## Version control

The `vcs` provider in `stopit default-config` (`type = "vcs"`, `name = "vcs"`, `profile = "main"`) masks the project's `.git` and `.jj` in `main`, contributes `vcs.ro`, `vcs.local`, and `vcs.remote` when the workspace is a repository, and attaches explicit `[provider.shims.jj]` and `[provider.shims.git]` rules. In non-repository directories it is a quiet no-op.

With the rules in `stopit default-config`:

- Reading and committing run at once: `git status`, `diff`, `log`, `show`, `add`, `commit`; `jj status`/`st`, `diff`, `log`, `show`, `evolog`, `op log`, `file show`, `new`, `commit`/`ci`, `describe`/`desc`.
- Commands that move or discard work ask you in the server's terminal: `git reset`, `rebase`, `checkout`, `switch`, `branch`, `tag`, `clean`, `stash`; `jj squash`, `rebase`, `abandon`, `restore`, `undo`, `bookmark`, `op`. So does anything not listed, and any call with a flag before the subcommand (`git --no-pager log` asks). Approve only commands you understand, since an approved command can write `.git`.
- Fetch and push (`git fetch`, `pull`, `ls-remote`, `remote update`, `clone`, `push`; `jj git fetch`, `git clone`, `git push`) run in `vcs.remote` (`decision = "ask"` in `default-config`; edit the rule in `config.toml` or `.stopit.toml` to `"allow"` or `"deny"` as you prefer), with `network = { mode = "full" }` and read-only binds of the host's `$SSH_AUTH_SOCK` and `~/.ssh/known_hosts`.
- Options that add configuration, name another repository or run other programs are refused via `flags = [...]` rules (`git -c`, `-C`, `--git-dir`; `jj --config`, `-R`, `--tool`, including short-flag clusters and unambiguous long-flag abbreviations).
- git and jj start no editor, pager or signing program, so `git commit` and `jj describe` need `-m`, and commits are not signed.
- The commands work only from inside the project. A `git` run from `/tmp` gets an error.

A refused command exits with 126 and says why on its stderr, as `[stopit: git: ...]`. Commits carry the `user.name` and `user.email` that `git config --global` gives on the host. jj's own user settings are not read.

The broker supports a plain git repository, a jj repository (colocated or not), a git worktree, and a jj secondary workspace (`jj workspace add`, with `[workspace] mount = "host"` when `.jj/repo` uses a relative path). A project below a checkout's root gets the mask without the broker, with a warning.

For projects whose build reads `.git` itself, edit `view = "ro"` on the `vcs` provider in `config.toml` (or replace `[[provider]] name = "vcs"` in `.stopit.toml`, copying `[provider.shims.*]` if you still want brokered shims). Showing `.git` read-only exposes `.git/config` too, including any credentials in remote URLs.

## More configuration

Each snippet below is a provider of its own. Every `[[provider]]` names `name`, `type`, and `profile` (only `name` is needed when `enabled = false`). Give each provider in one file a distinct `name`, or merge them into one.

### Edit Nix files in a NixOS or module repository

`stopit default-config` keeps `{workspace}/**/*.nix` and `{workspace}/flake.lock` in a separate `protect-nix` provider so projects that evaluate Nix on the host stay read-only while a NixOS configuration or Nix library repository can turn that off in `.stopit.toml` and edit Nix files directly in `main`:

```toml
[[provider]]
name = "protect-nix"
enabled = false
```

If you also enabled `name = "nix"` globally in `config.toml`, disable `name = "nix"` in `.stopit.toml` as well so host `nix` evaluation does not import modified `.nix` files on later runs.

To keep `protect-nix` on and make only specific files writable in `main`, override them in a workspace provider (workspace rules beat global rules of equal specificity):

```toml
[[provider]]
name = "allow-modules"
type = "config"
profile = "main"
[provider.sandbox]
fs.rw = ["{workspace}/modules/**/*.nix"]
```

To ignore `~/.config/stopit/config.toml` altogether in a self-contained project configuration, set `inherit_global = false` at the top of `.stopit.toml`.

### Let a build reach the internet

```toml
[[provider]]
name = "crates"
type = "config"
profile = "main"
[provider.sandbox]
network = { mode = "proxy", allow_domains = ["index.crates.io", "static.crates.io"] }
```

Tools find the proxy through `HTTPS_PROXY` and the other proxy variables, which stopit sets. `network = { mode = "full" }` gives the sandbox a network of its own, connected to yours by `pasta`. Only DNS queries reach your machine's loopback there.

### Keep a build cache between sessions

`ephemeral` directories start empty and are deleted at the end of the session. To keep a cache, grant a host directory read-write instead:

```toml
[[provider]]
name = "cargo-cache"
type = "config"
profile = "main"
[provider.sandbox]
fs.rw = ["~/.cargo/registry"]
env.set = { CARGO_HOME = "/home/stopit/.cargo" }
```

`~` in a rule means your host home directory for the source and the sandbox home (`/home/stopit` by default, or `/home/<username>` when `system.user` sets a sandbox username) for where it appears. stopit refuses a read-write grant that contains its own state directories, so `rw ~` does not work. Grant narrower paths.

### Use your host username or pass through host devices

Tools that derive credential paths from your username or `/etc/passwd`, or emulators that need `/dev/kvm` or `/dev/net/tun`, can configure `system.user` and `system.devices`:

```toml
[[provider]]
name = "host-identity-and-devices"
type = "config"
profile = "main"
[provider.sandbox]
system.user = "host"   # or { username = "builder" }; sets default home to /home/<username>
system.devices = ["/dev/kvm", "/dev/net/tun"]
```

### Hide or protect more files

```toml
[[provider]]
name = "rules"
type = "config"
profile = "main"
[provider.sandbox]
fs.masked = ["{workspace}/config/credentials.yml"]
fs.protected = ["{workspace}/Makefile", "{workspace}/scripts/**"]
fs.ephemeral = ["{workspace}/target"]
```

- `masked` shows the path empty and unreadable.
- `protected` is read-only for now. A later version will ask you to approve each write.
- `ephemeral` gives a writable, empty directory that is discarded at the end of the session, here so build output never lands in your project.
- `fs.warn_missing = false` suppresses startup warnings when rules in a shared provider name files not every project has.

The most specific rule wins. An exact path beats a glob, a workspace rule beats a global rule of the same specificity, and within one layer the stricter mode wins.

### Brokered commands of your own

A shim runs a command in a fresh sandbox of another profile. Its rules pick the profile and decide whether to allow, ask or deny. Here `cargo publish` asks, and runs in a profile that can reach crates.io:

```toml
[profiles.publish]
inherit = "main"

[[provider]]
name = "cargo-shim"
type = "config"
profile = "main"
[provider.sandbox]
shims.cargo = { cmd = "cargo", default = { decision = "allow", profile = "main" }, rules = [
  { flags = ["--config"], decision = "deny" },
  { prefix = "publish", decision = "ask", profile = "publish" },
] }

[[provider]]
name = "publish"
type = "config"
profile = "publish"
[provider.sandbox]
network = { mode = "proxy", allow_domains = ["crates.io", "index.crates.io", "static.crates.io"] }
```

The publish profile still has no registry token, since the default filter drops `CARGO_REGISTRY_TOKEN`. In `cmd = ["binary", ...args]`, standalone `"{workspace}"` and `"{workspace}/..."` arguments expand to the sandbox workspace mount (pass flags and paths as separate arguments, such as `cmd = ["jj", "-R", "{workspace}"]`). Rules are evaluated in first-match-wins order against the caller's arguments (`literal`, `prefix`, `regex`, or `flags` for short-flag clusters and long-flag prefix abbreviations). For full custom argument parsing or dynamic per-invocation profiles, set `proxy = "./my-proxy.sh"` on a shim instead. Set `tty = true` on a shim for a full-screen TUI or interactive shell so foreground terminal calls get a pseudo-terminal and window-size updates of their own. Set `shims.<name> = false` (or `{ enabled = false }`) to disable a shim inherited from a parent profile or lower layer, and `enabled = false` on a `[[provider]]` to disable a provider by name. DESIGN.md section 7.1 describes the rules.

### Mount the project at its host path

Agents and build caches that record the working directory on the host break if a resumed session sees `/workspace` instead. Set `mount = "host"` in `~/.config/stopit/config.toml` or `.stopit.toml` to mount each project at its canonical host path:

```toml
[workspace]
mount = "host"
```

### Let a command ask for more

A command in the sandbox, usually the agent, can ask for more network or files for one command with `stopit-grant`. You answer in the server's terminal:

```sh
stopit-grant +net:crates.io +ro:~/.cargo/credentials.toml -- cargo publish
```

- `+net:<domain>` reaches a domain through the proxy, and `+net:full` gives the full network.
- `+rw:<path>` and `+ro:<path>` mount a host path. The path is absolute, or `~/…` for your home.
- The command runs in a sandbox like the caller's, plus the grants, and gets nothing else. It cannot call `stopit-grant` again.
- stopit refuses, before asking you, what it would refuse in your configuration, such as your project at a second path or stopit's own state. It also refuses a writable path holding files another profile mounts, and a path the caller's profile masks. The sandbox is told only that it was refused, and your server's terminal says why.
- `s` allows the same grants again for the rest of the session, for commands in a scope, and `p` also saves the grants to `.stopit.toml`. The agent can propose the scope with `--scope 'cargo publish'`. Otherwise it is the program and its subcommand words. The prompt shows it.
- After you say no, every `stopit-grant` from that profile is refused for five seconds without asking.
- `sandbox.grant = false` in a provider removes `stopit-grant` from that profile and the ones inheriting it.

### Limit processes, memory and CPU

```toml
[limits]
pids   = 4096
memory = "8G"
cpu    = "400%"   # of one CPU
```

The limits cover the whole session, which is one run, or a server with all its runs. stopit asks your systemd for a scope of its own and refuses to start unless the limits are in place there.

### Use a Nix development shell

Add `[[provider]] type = "nix"` in `~/.config/stopit/config.toml` or `.stopit.toml` to resolve a project's Nix development shell on the host and mount only its runtime closure inside the sandbox, without exposing all of `/nix/store` or the Nix daemon:

```toml
[[provider]]
name = "nix"
type = "nix"
profile = "main"
```

When placed after fallback host tool providers in `config.toml`, the development shell's `PATH` entries precede host tools in projects that have a `flake.nix` or `shell.nix`, and the provider does nothing in projects that have neither. In `.stopit.toml`, customize it per project (matching `name = "nix"` replaces the global entry cleanly):

```toml
[[provider]]
name = "nix"
type = "nix"
profile = "main"
shell = "agent"            # devShells.<system>.agent on flakes, or attribute agent on shell.nix
# file = "nix/ci.nix"      # evaluate a specific classic Nix file (mutually exclusive with flake)
# flake = "nix"            # evaluate a flake in another directory
# cache = true             # cache resolved closures + GC roots in ~/.local/share/stopit/nix
# shell_hook = true        # run non-empty shellHook inside the sandbox before the command
```

`flake.lock` is never modified during evaluation, `shellHook` is never run on the host and instead executes inside the sandbox right before the target command via the development shell's `bash` (`shell_hook = false` disables it, and `vcs` profiles clear inherited hooks so brokered `git` and `jj` calls stay fast and clean), exported variables from the shell (other than internal `stdenv`, sandbox identity, and proxy variables) are applied to the profile, and closures containing secret-bearing derivations (`*-etc`, `*-home-manager-files`, `*nix.conf*`) are refused. Set `enabled = false` on `[[provider]] name = "nix"` in `.stopit.toml` for a library or module flake that defines no development shell or default package.

### Generate grants with a script

A script provider runs on your host at every start and prints a manifest as JSON. Use it to compute grants, for example from a development shell:

```toml
[[provider]]
name = "env-script"
type = "script"
profile = "main"
source = "scripts/stopit-env.sh"
```

The script runs with your privileges, so stopit protects it in every sandbox (`protect = true` is the default) and refuses to run one that a sandbox could have changed. DESIGN.md section 3.6 describes the manifest format.

### Run from a subdirectory or another directory

stopit walks up from the current directory to the nearest `.stopit.toml`. That directory is the workspace (`stopit init` creates `.stopit.toml` in the current directory when starting a new workspace). `--workspace DIR` picks the workspace explicitly. If a directory above also has a `.stopit.toml` you own, stopit refuses to start, because a sandbox could have planted the inner one. Pass `--workspace` to choose.

## Managing allowed configurations

```sh
stopit init                       # create an empty .stopit.toml and allow it
stopit allow                      # allow an existing or replaced .stopit.toml
stopit allowed                    # list allowed configurations
stopit revoke                     # remove the current one
stopit revoke PATH                # remove an entry by path, even if the project is gone
```

Allowed configurations are recorded by canonical path and file identity (`dev`, `ino`, and `btime`) in `~/.local/share/stopit/allowed.json`. No sandbox can write there, and every valid allowed `.stopit.toml` is protected across sandboxes even when an `fs.rw` grant covers another workspace. `stopit allowed` marks deleted files `(missing)` and recreated or atomic-renamed files `(replaced)`.

`stopit allow` trusts the file as it is when you run it, so read it first, especially after cloning a repository or after an agent has worked in a directory.

## Startup summary

Before the sandbox starts, `stopit run` and `stopit shell` print to stderr what the profile grants: mounts of host content outside the workspace or wider than the workspace's own mount, unmasked sockets, network access (`proxy` or `full`), passed-through host devices, shared namespaces, re-enabled syscalls, brokered commands, script providers with `protect = false`, and environment variable `pass` patterns and `set` names (never values). `-q` / `--quiet` leaves the summary out (warnings and errors are still printed). Give it before the command, since after it `-q` is the command's own.

## Current limitations

- `protected` files are read-only. There is no approval prompt for writes yet.
- `stopit-grant` cannot grant secrets or an SSH agent yet.
- The proxy reaches ports 443 and 80 only, so SSH needs `full` mode.
- A prompt holds up the run's output until you answer it.
- `tty` and `ttyname` fail inside the sandbox.
- Editors or host VCS commands that replace `.stopit.toml` via write-and-rename create a new file identity and require `stopit allow` once afterwards.
- A sandbox can create files that host tools run or trust where none existed when the session started: a `.git` in a subdirectory, or in the project when it has none, a `flake.nix`, `flake.lock` or `shell.nix` when `type = "nix"` is enabled in a project that lacked them, or agent and editor settings such as `.claude/`, `.gemini/`, `.mcp.json`, `opencode.json`, `.opencode/`, `.codex/` and `.vscode/`. Look before running git, nix or an agent on the host there.

DESIGN.md section 11 has the complete list.

## License

Not yet chosen.
