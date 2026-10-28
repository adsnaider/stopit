# stopit

stopit runs a program, such as an LLM coding agent, a shell or a build, in a Linux sandbox. The sandbox sees your project and little else. Your home directory, SSH keys, cloud credentials and tokens in the environment stay out of reach unless the project's configuration grants them.

It is a single Rust binary built on [bubblewrap](https://github.com/containers/bubblewrap). Each session's policy comes from a `.stopit.toml` in the project, and stopit refuses to use one until you have reviewed and allowed it.

> **Status: early development.** The filesystem, environment and configuration-trust parts work and are tested against real sandboxes. Seccomp, Landlock, network filtering, the terminal proxy and brokered tools (`git`, `jj`) are not built yet. Do not rely on stopit to contain hostile code yet. [DESIGN.md](DESIGN.md) describes the full design, and its section 11 lists what is missing.

## What the sandbox gets by default

With an empty `.stopit.toml` (or none), a sandbox has:

- your project, read-write, at `/workspace`, which is also the working directory;
- secrets in the project masked: `.env`, `.env.*`, `*.pem`, `*.key`, `.npmrc` and `.pypirc` show up empty and unreadable;
- files that would let it escape on your next run made read-only: `.stopit.toml`, `*.nix`, `flake.lock`, `.envrc`, `.vscode`, `.idea` and `.github/workflows`;
- an empty home directory at `/home/user` and an empty `/tmp`, both deleted when the session ends;
- its own `/proc` and a minimal `/dev`;
- generated `/etc/passwd`, `/etc/group`, `/etc/hosts` and `/etc/nsswitch.conf` naming the user `user` and the host `stopit`;
- loopback networking only;
- an environment holding `HOME`, `USER`, `LOGNAME`, plus `TERM`, `LANG` and `COLORTERM` from yours. Variables matching `*_TOKEN`, `*_KEY`, `*_SECRET`, `*_PASSWORD`, `AWS_*`, `GITHUB_*`, `SSH_AUTH_SOCK` or `NIX_CONFIG` are never passed, in any letter case.

It gets no programs. `/usr`, `/bin` and `/nix/store` are not mounted, so the first thing most configurations do is grant your tools (see below).

## Requirements

- Linux 5.9 or newer with unprivileged user namespaces enabled.
- bubblewrap 0.12 or newer on `PATH`.
- `$XDG_RUNTIME_DIR` set to a private directory, as systemd login sessions do.
- Rust 1.85 or newer to build.

## Build

```sh
cargo build --release
```

The binary is `target/release/stopit`. With Nix, `nix develop` gives a shell with the toolchain and bubblewrap.

## Quick start

1. Create a configuration in your project and allow it:

   ```sh
   cd ~/Projects/myproject
   touch .stopit.toml
   stopit allow
   ```

   `stopit allow` prints the file's size and SHA-256. Run it again after every change to `.stopit.toml`. Until you do, `stopit run` refuses to start.

2. Run a command:

   ```sh
   stopit run ls -la /workspace
   stopit shell                 # runs $SHELL, which must exist in the sandbox
   ```

   The command's exit code is passed through. stopit's own errors exit with 125.

An empty configuration grants no programs, so these commands fail until you grant some. The scenarios below show how.

## Scenarios

### Run tools on NixOS

Grant the store and the system profile, and put its `bin` first in `PATH`:

```toml
[[provider]]
type = "config"
[provider.sandbox]
fs.ro = ["/nix/store", "/run/current-system/sw"]
env.path_prepend = ["/run/current-system/sw/bin"]
```

Granting all of `/nix/store` is fine for trying stopit out. On NixOS the store can hold rendered secrets, so a real setup should grant only the paths a development shell needs (DESIGN.md section 3.6).

### Run tools on Debian, Ubuntu or Fedora

```toml
[[provider]]
type = "config"
[provider.sandbox]
fs.ro = ["/usr", "/bin", "/lib", "/lib64", "/etc/alternatives"]
env.path_prepend = ["/usr/local/bin", "/usr/bin", "/bin"]
```

Links outside your project, such as `/bin -> usr/bin`, are followed.

### Let a build reach the internet

```toml
[[provider]]
type = "config"
[provider.sandbox]
network = { mode = "full" }
fs.ro = ["/etc/ssl/certs", "/etc/resolv.conf"]
```

`full` shares your network. The planned `proxy` mode, which allows only listed domains, is not built yet.

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

### Give an agent its own profile

A profile is a complete sandbox description. `main` is used unless you pass `--profile`:

```toml
[profiles.agent]          # starts from everything main grants

[[provider]]
type = "config"
profile = "agent"
[provider.sandbox]
network = { mode = "full" }
fs.rw = ["~/.config/my-agent"]
```

```sh
stopit run --profile agent my-agent
```

Use `inherit = "none"` in the profile to start from an empty sandbox instead.

### Generate grants with a script

A script provider runs on your host at every start and prints a manifest as JSON. Use it to compute grants, for example from a development shell:

```toml
[[provider]]
type = "script"
source = "scripts/stopit-env.sh"
```

The script runs with your privileges, so stopit protects it in every sandbox (`protect = true` is the default) and refuses to run one that a sandbox could have changed. DESIGN.md section 3.6 describes the manifest format.

### Run from a subdirectory or another directory

stopit walks up from the current directory to the nearest `.stopit.toml`. That directory is the workspace. `--workspace DIR` picks it explicitly. If a directory above also has a `.stopit.toml` you own, stopit refuses to start, because a sandbox could have planted the inner one. Pass `--workspace` to choose.

## Managing allowed configurations

```sh
stopit allow                      # allow the current .stopit.toml as it is now
stopit allowed                    # list allowed configurations
stopit revoke                     # remove the current one
stopit revoke PATH                # remove an entry by path, even if the project is gone
```

Allowed configurations are recorded by path and content hash in `~/.local/share/stopit`. No sandbox can write there. If an allowed `.stopit.toml` disappears, stopit refuses to fall back to the defaults until you restore it or revoke it.

`stopit allow` trusts the file as it is when you run it, so read it first, especially after an agent has worked in the project.

## Current limitations

- No terminal proxy yet. The sandbox shares your terminal in its own session, so job control is off: Ctrl-Z is ignored and starting stopit in the background is refused.
- No seccomp or Landlock filters yet. Mount namespaces and bubblewrap are the only boundary.
- `network = "none"` still has loopback up. Domain filtering is not built.
- `protected` files are read-only. There is no approval prompt.
- No brokered tools (`git`, `jj`) and no startup summary of what each sandbox can reach.
- Script providers are not hashed by `stopit allow`. A script you change after allowing still runs.

DESIGN.md section 11 has the complete list.

## License

Not yet chosen.
