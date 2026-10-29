# stopit

stopit runs a program, such as an LLM coding agent, a shell or a build, in a Linux sandbox. The sandbox sees your project and little else. Your home directory, SSH keys, cloud credentials and tokens in the environment stay out of reach unless the configuration grants them.

It is a single Rust binary built on [bubblewrap](https://github.com/containers/bubblewrap), Landlock and seccomp. Agents with full-screen terminal interfaces (Claude Code, Gemini CLI, Codex, OpenCode) run in it through a terminal proxy that filters what they may send to your terminal. `git` and `jj` run through a broker that keeps the repository's metadata out of the agent's reach.

> **Status: usable, still young.** The sandbox, the configuration and its trust checks, the terminal proxy, `stopit server` with its prompts, the `full` and `proxy` network modes, brokered `git` and `jj` for local work, and resource limits work and are tested against real sandboxes. Fetch and push through the broker, prompts for writes to protected files, `stopit-grant` and saved approvals are not built yet. [DESIGN.md](DESIGN.md) describes the design, and its section 11 lists what is missing.

## What the sandbox gets by default

With an empty `.stopit.toml` (or none), a sandbox has:

- your project, read-write, at `/workspace`, which is also the working directory;
- secrets in the project masked: `.env`, `.env.*`, `*.pem`, `*.key`, `.npmrc` and `.pypirc` show up empty and unreadable;
- files that would let it escape on your next run made read-only: `.stopit.toml`, `*.nix`, `flake.lock`, `.envrc`, `.vscode`, `.idea`, `.github/workflows`, agent settings such as `.claude` and `.gemini`, and others (DESIGN.md, Appendix A);
- the repository's `.git` and `.jj` masked, with `git` and `jj` brokered instead (see [Version control](#version-control));
- an empty home directory at `/home/user` and an empty `/tmp`, both deleted when the session ends;
- its own `/proc` and a minimal `/dev`;
- generated `/etc/passwd`, `/etc/group`, `/etc/hosts` and `/etc/nsswitch.conf` naming the user `user` and the host `stopit`;
- loopback networking only;
- an environment holding `HOME`, `USER`, `LOGNAME`, plus `TERM`, `LANG` and `COLORTERM` from yours. Variables matching `*_TOKEN`, `*_KEY`, `*_SECRET`, `*_PASSWORD`, `AWS_*`, `GITHUB_*`, `SSH_AUTH_SOCK` or `NIX_CONFIG` are never passed, in any letter case.

It gets no programs. `/usr`, `/bin` and `/nix/store` are not mounted, so the first thing a configuration does is grant your tools (see below).

## Requirements

- Linux 5.13 or newer with unprivileged user namespaces enabled, and Landlock.
- bubblewrap 0.12 or newer on `PATH`.
- `$XDG_RUNTIME_DIR` set to a private directory, as systemd login sessions do.
- For `network = "full"`: `pasta` from the passt package.
- For `[limits]`: a systemd user session, `busctl`, and cgroup v2.
- Rust 1.88 or newer to build.

## Install

```sh
cargo build --release      # the binary is target/release/stopit
```

With Nix, `nix build` gives a `stopit` that finds bubblewrap and pasta on its own, and `nix develop` a shell with the toolchain. The flake also has a Home Manager module:

```nix
imports = [ stopit.homeModules.default ];   # adds stopit to home.packages
```

## Quick start

1. Grant your tools once for every project, in `~/.config/stopit/config.toml`. On Debian, Ubuntu or Fedora:

   ```toml
   [[provider]]
   name = "tools"
   type = "config"
   [provider.sandbox]
   fs.ro = ["/usr", "/bin", "/lib", "/lib64", "/etc/alternatives", "/etc/ssl/certs"]
   env.path_prepend = ["/usr/local/bin", "/usr/bin", "/bin"]
   ```

   On NixOS:

   ```toml
   [[provider]]
   name = "tools"
   type = "config"
   [provider.sandbox]
   fs.ro = ["/nix/store", "/run/current-system/sw", "/etc/ssl/certs"]
   env.path_prepend = ["/run/current-system/sw/bin"]
   ```

   Packages from Home Manager live in `/nix/store` too. Add the `bin` directory of your profile, as an absolute path, to `env.path_prepend`. Granting all of `/nix/store` is fine for trying stopit out. On NixOS the store can hold rendered secrets, so a careful setup grants only the paths a development shell needs (DESIGN.md section 3.6).

   This file needs no `stopit allow`: stopit trusts it because only you can write it, and it checks that no sandbox can.

2. Run a command in a project:

   ```sh
   cd ~/Projects/myproject
   stopit run ls -la /workspace
   stopit shell                 # runs $SHELL, which must exist in the sandbox
   ```

   The command's exit code is passed through. stopit's own errors exit with 125.

3. To change what a project's sandboxes get, add a `.stopit.toml` and allow it:

   ```sh
   $EDITOR .stopit.toml
   stopit allow
   ```

   `stopit allow` prints the file's size and SHA-256. Run it again after every change. Until you do, `stopit run` refuses to start, so a change you did not review never takes effect.

## Running agents

### The server

Start a server in the project in one terminal, and run the agent from another:

```sh
stopit server                         # terminal 1, stays in the foreground
stopit run --profile claude claude    # terminal 2
```

`stopit run` and `stopit shell` attach to the project's server when one runs, so every run shares one session: one `/tmp`, one home, the same brokers. Questions for you, such as whether a brokered command may run or whether the agent may write to your clipboard, appear in the server's terminal, never in the agent's, so the agent cannot draw a fake prompt or answer one. Without a server, anything that needs a yes is refused. `--standalone` runs without the server, and `--server ID` picks one by the id it prints.

### Profiles for agents

A profile is a complete sandbox description. `main` is used unless you pass `--profile`. Put an agent's profile in `~/.config/stopit/config.toml` next to the tools, so every project has it. Each recipe below grants the agent's own state directory read-write and lets it reach only its provider's API, through stopit's filtering proxy.

Create each state directory on the host first. stopit skips a rule whose path is missing, with a warning, and the agent's state then lands in the session's home and is gone when the session ends.

The proxy lets a tool reach only the listed names, on ports 443 and 80, and prints the names it refused when the run ends. If an agent cannot log in or fetch something, add the names it lists, or use `network = { mode = "full" }`, which reaches whatever your machine reaches except services on its loopback. Log in on the host first. Login flows that open a browser and wait on a local port cannot reach a sandbox.

The agent's program must be visible in the sandbox too. Installed through Nix or the system's packages, the tools provider covers it. Installed with npm into your home, grant that prefix, as in the Gemini recipe. A launcher that is a link with an absolute path into your home (`~/.local/bin/claude` to `/home/you/.local/share/claude/...`) needs its target granted at that same absolute path.

**Claude Code**

```toml
[profiles.claude]

[[provider]]
name = "claude"
type = "config"
profile = "claude"
[provider.sandbox]
fs.rw = ["~/.claude"]
env.set = { CLAUDE_CONFIG_DIR = "/home/user/.claude" }
network = { mode = "proxy", allow_domains = ["api.anthropic.com", "statsig.anthropic.com", "console.anthropic.com", "claude.ai"] }
```

`CLAUDE_CONFIG_DIR` keeps Claude Code's settings and login in `~/.claude`, the one directory granted, rather than also in `~/.claude.json`. The project's `.claude` directory stays read-only, so the agent cannot change its own permissions or hooks there.

**Gemini CLI**

```toml
[profiles.gemini]

[[provider]]
name = "gemini"
type = "config"
profile = "gemini"
[provider.sandbox]
fs.rw = ["~/.gemini"]
fs.ro = ["~/.npm-global"]
env.path_prepend = ["/home/user/.npm-global/bin"]
network = { mode = "proxy", allow_domains = ["generativelanguage.googleapis.com", "cloudcode-pa.googleapis.com", "oauth2.googleapis.com", "play.googleapis.com"] }
```

`~/.npm-global` stands for wherever `npm install -g` put it. Gemini CLI reads its key from `GEMINI_API_KEY`, which the default filter drops (`*_KEY`). Prefer the login it keeps in `~/.gemini`, or set the key with `env.set` in the provider, which the filter does not touch, knowing that the configuration file then holds it.

**Codex**

```toml
[profiles.codex]

[[provider]]
name = "codex"
type = "config"
profile = "codex"
[provider.sandbox]
fs.rw = ["~/.codex"]
network = { mode = "proxy", allow_domains = ["api.openai.com", "chatgpt.com", "auth.openai.com"] }
```

Codex has a sandbox of its own. If it reports that it cannot start it inside stopit, run it with `--sandbox danger-full-access`, and stopit is the boundary.

**OpenCode**

```toml
[profiles.opencode]

[[provider]]
name = "opencode"
type = "config"
profile = "opencode"
[provider.sandbox]
fs.rw = ["~/.config/opencode", "~/.local/share/opencode", "~/.cache/opencode"]
network = { mode = "proxy", allow_domains = ["models.dev", "registry.npmjs.org", "api.anthropic.com", "api.openai.com"] }
```

List the API of each model provider you use with it.

### What an agent sees

- **Your terminal, through a proxy.** stopit gives the sandbox a terminal of its own and copies its output to yours, dropping escape sequences that could rewrite your terminal's settings or title, or read it back. Colors, cursor movement, the alternate screen and mouse reporting pass. Writes to your clipboard (OSC 52) are blocked. With `[terminal] clipboard_write = "ask"`, each waits for your answer in the server's terminal (DESIGN.md section 5).
- **Version control** through the broker (next section).
- **Nothing of your home** beyond what a profile grants. The sandbox home is empty and shared by the session's runs.

## Version control

The `vcs` provider, on by default, masks the project's `.git` and `.jj` in the sandbox and puts `git` and `jj` commands on its `PATH` that ask stopit's broker to run the real ones, in a sandbox of their own that can write the repository but not the network.

- Reading and committing run at once: `git status`, `diff`, `log`, `show`, `add`, `commit`; `jj status`, `diff`, `log`, `show`, `new`, `commit`, `describe`.
- History rewriting asks you in the server's terminal: `git reset`, `rebase`, `checkout`, `switch`, `branch`, `tag`, `clean`, `stash`; `jj squash`, `rebase`, `abandon`, `restore`, `undo`, `bookmark`, `op`. So does anything not listed.
- Fetch and push are refused. Run them on the host.
- Options that add configuration, name another repository or run other programs are refused (`git -c`, `-C`, `--git-dir`; `jj --config`, `-R`, `--tool`).
- git and jj start no editor, pager or signing program, so `git commit` and `jj describe` need `-m`.

A refused command exits with 126 and says why on its stderr, as `[stopit: git: ...]`. Commits carry your `user.name` and `user.email` from `~/.gitconfig`.

The broker supports a plain repository, a colocated jj repository and a git worktree. Others (a jj secondary workspace, a project below a checkout's root) get the mask without the broker, with a warning. Some builds of jj need `/sys/devices/system/cpu` granted read-only to start.

Use `vcs` with `view = "ro"` for projects whose build reads `.git` itself:

```toml
[[provider]]
type = "vcs"
view = "ro"
```

## More configuration

### Let a build reach the internet

```toml
[[provider]]
type = "config"
[provider.sandbox]
network = { mode = "proxy", allow_domains = ["index.crates.io", "static.crates.io"] }
```

Tools find the proxy through `HTTPS_PROXY` and the other proxy variables, which stopit sets. `network = { mode = "full" }` gives the sandbox a network of its own, connected to yours by `pasta`. Only DNS queries reach your machine's loopback there.

### Keep a build cache between sessions

`ephemeral` directories start empty and are deleted at the end of the session. To keep a cache, grant a host directory read-write instead:

```toml
[[provider]]
type = "config"
[provider.sandbox]
fs.rw = ["~/.cargo/registry"]
env.set = { CARGO_HOME = "/home/user/.cargo" }
```

`~` in a rule means your host home directory for the source and the sandbox home (`/home/user`) for where it appears. stopit refuses a read-write grant that contains its own state directories, so `rw ~` does not work. Grant narrower paths.

### Hide or protect more files

```toml
[[provider]]
type = "config"
[provider.sandbox]
fs.masked = ["{workspace}/config/credentials.yml"]
fs.protected = ["{workspace}/Makefile", "{workspace}/scripts/**"]
fs.ephemeral = ["{workspace}/target"]
```

- `masked` shows the path empty and unreadable.
- `protected` is read-only for now. A later version will ask you to approve each write.
- `ephemeral` gives a writable, empty directory that is discarded at the end of the session, here so build output never lands in your project.

The most specific rule wins: an exact path beats a glob, and between rules for the same path the stricter mode wins.

### Brokered commands of your own

A shim runs a command in another profile, after the rules you give it, and asks when they say `ask`:

```toml
[profiles.publish]

[[provider]]
type = "config"
[provider.sandbox]
shims.cargo = { binary = "cargo", deny_flags = ["--config"], default = { decision = "allow", profile = "main" }, rules = [
  { subcommand = ["publish"], decision = "ask", profile = "publish" },
] }
```

DESIGN.md section 7.1 describes the rules.

### Limit processes, memory and CPU

```toml
[limits]
pids   = 4096
memory = "8G"
cpu    = "400%"   # of one CPU
```

The limits hold for the session as a whole: a run, or a server and all its runs. stopit asks your systemd for a scope of its own and refuses to start unless the limits are in place there.

### Generate grants with a script

A script provider runs on your host at every start and prints a manifest as JSON. Use it to compute grants, for example from a development shell:

```toml
[[provider]]
type = "script"
source = "scripts/stopit-env.sh"
```

The script runs with your privileges, so stopit protects it in every sandbox (`protect = true` is the default) and refuses to run one that a sandbox could have changed. DESIGN.md section 3.6 describes the manifest format.

### Run from a subdirectory or another directory

stopit walks up from the current directory to the nearest `.stopit.toml`. That directory is the workspace, or the current directory if there is none. `--workspace DIR` picks it explicitly. If a directory above also has a `.stopit.toml` you own, stopit refuses to start, because a sandbox could have planted the inner one. Pass `--workspace` to choose.

## Managing allowed configurations

```sh
stopit allow                      # allow the current .stopit.toml as it is now
stopit allowed                    # list allowed configurations
stopit revoke                     # remove the current one
stopit revoke PATH                # remove an entry by path, even if the project is gone
```

Allowed configurations are recorded by path and content hash in `~/.local/share/stopit`. No sandbox can write there. If an allowed `.stopit.toml` disappears, stopit refuses to fall back to the defaults until you restore it or revoke it.

`stopit allow` trusts the file as it is when you run it, so read it first, especially after an agent has worked in the project.

## Startup summary

Before the sandbox starts, `stopit run` and `stopit shell` print to stderr what the profile grants beyond the default base: mounts of host content outside the workspace or wider than the workspace's own mount, unmasked sockets, network access, shared namespaces, re-enabled syscalls, brokered commands, script providers with `protect = false`, and extra environment variable names (never values). `-q` / `--quiet` leaves the summary out (warnings and errors are still printed). Give it before the command, since after it `-q` is the command's own.

## Current limitations

- Brokered `git` and `jj` cannot fetch or push. Run those on the host.
- `protected` files are read-only. There is no approval prompt for writes yet.
- Answers to prompts last for the session at most. Nothing is saved to `.stopit.toml`.
- `stopit-grant`, to ask for one more grant for one command, is not built.
- Script providers are not hashed by `stopit allow`. A script you change after allowing still runs.
- A sandbox can create a `.git` in a subdirectory, or in the project when it has none, which `git` on the host then trusts. Look before running `git` there.

DESIGN.md section 11 has the complete list.

## License

Not yet chosen.
