//! Gitignore and ignore rule matching for the Nix provider (DESIGN.md §3.6).
//!
//! Evaluates `.gitignore` files and explicit `provider.ignore` patterns when
//! walking workspace trees for validation, persistent cache hashing, and
//! temporary flake staging.

use core::fmt;
use std::path::{Path, PathBuf};

use globset::{Glob, GlobBuilder, GlobMatcher};

use crate::config::NixIgnorePattern;

/// An ignore rule matcher.
#[derive(Clone)]
enum RuleMatcher {
    /// Matches any file or directory (`**`).
    All,
    /// Matches against a single path component / file name (unanchored pattern without `/`).
    Basename(GlobMatcher),
    /// Matches against a relative path from the rule's anchoring directory.
    Anchored(GlobMatcher),
}

impl fmt::Debug for RuleMatcher {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::All => write!(f, "All"),
            Self::Basename(_) => write!(f, "Basename(..)"),
            Self::Anchored(_) => write!(f, "Anchored(..)"),
        }
    }
}

/// A compiled ignore rule.
#[derive(Debug, Clone)]
struct CompiledRule {
    /// Whether this rule is negated (`!pattern`), re-including matched paths.
    negated: bool,
    /// Whether this rule applies only to directories (`pattern/`).
    dir_only: bool,
    /// The glob matcher.
    matcher: RuleMatcher,
}

/// A layer of rules parsed from a `.gitignore` file at `base_rel`.
#[derive(Debug, Clone)]
pub struct RuleLayer {
    /// Relative directory of the `.gitignore` file from the target root.
    base_rel: PathBuf,
    /// Ordered rules parsed from this `.gitignore`.
    rules: Vec<CompiledRule>,
}

impl RuleLayer {
    /// Parses `.gitignore` file content into a [`RuleLayer`] anchored at `base_rel`.
    ///
    /// Malformed glob patterns are ignored gracefully, matching Git behavior.
    pub fn from_gitignore_bytes(base_rel: &Path, content: &str) -> Self {
        let mut rules = Vec::new();
        for raw_line in content.lines() {
            let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
            if let Some(rule) = parse_gitignore_line(line) {
                rules.push(rule);
            }
        }
        Self {
            base_rel: base_rel.to_path_buf(),
            rules,
        }
    }
}

/// Strips unescaped trailing spaces from a `.gitignore` line.
///
/// Trailing spaces are kept only if escaped with `\`.
fn strip_unescaped_trailing_spaces(mut s: &str) -> &str {
    while s.ends_with(' ') {
        let before_space = &s[..s.len() - 1];
        let trailing_backslashes = before_space
            .bytes()
            .rev()
            .take_while(|&b| b == b'\\')
            .count();
        if trailing_backslashes % 2 != 0 {
            // The trailing space is escaped by an odd number of backslashes.
            break;
        }
        s = before_space;
    }
    s
}

/// Checks if the trailing slash of `s` is unescaped and strips it if present.
fn strip_unescaped_trailing_slash(mut s: &str) -> (&str, bool) {
    let mut dir_only = false;
    while s.ends_with('/') {
        let before_slash = &s[..s.len() - 1];
        let trailing_backslashes = before_slash
            .bytes()
            .rev()
            .take_while(|&b| b == b'\\')
            .count();
        if trailing_backslashes % 2 != 0 {
            break;
        }
        dir_only = true;
        s = before_slash;
    }
    (s, dir_only)
}

/// Compiles a single glob pattern into a [`RuleMatcher`].
fn compile_rule_matcher(pat: &str, anchored: bool) -> Result<RuleMatcher, globset::Error> {
    if pat == "**" {
        return Ok(RuleMatcher::All);
    }
    if !anchored {
        let glob = GlobBuilder::new(pat).literal_separator(true).build()?;
        return Ok(RuleMatcher::Basename(glob.compile_matcher()));
    }
    let glob = compile_anchored_glob(pat)?;
    Ok(RuleMatcher::Anchored(glob.compile_matcher()))
}

/// Compiles a slash-sensitive glob anchored to the layer base.
fn compile_anchored_glob(pat: &str) -> Result<Glob, globset::Error> {
    GlobBuilder::new(pat).literal_separator(true).build()
}

/// Parses a single line of a `.gitignore` file.
fn parse_gitignore_line(line: &str) -> Option<CompiledRule> {
    let trimmed = strip_unescaped_trailing_spaces(line);
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }

    let (pat, negated) = if let Some(rest) = trimmed.strip_prefix('!') {
        (rest, true)
    } else {
        (trimmed, false)
    };

    let (pat_no_trailing_slash, dir_only) = strip_unescaped_trailing_slash(pat);
    if pat_no_trailing_slash.is_empty() {
        return None;
    }

    let anchored = pat_no_trailing_slash.contains('/');
    let pat_clean = pat_no_trailing_slash.strip_prefix('/').unwrap_or(pat_no_trailing_slash);
    if pat_clean.is_empty() {
        return None;
    }

    let matcher = compile_rule_matcher(pat_clean, anchored).ok()?;
    Some(CompiledRule {
        negated,
        dir_only,
        matcher,
    })
}

/// Compiles explicit `provider.ignore` patterns into [`CompiledRule`]s.
fn compile_explicit_ignore(patterns: &[NixIgnorePattern]) -> Vec<CompiledRule> {
    let mut rules = Vec::with_capacity(patterns.len());
    for pat_wrapper in patterns {
        let s = pat_wrapper.as_str();
        let (pat_no_trailing_slash, dir_only) = strip_unescaped_trailing_slash(s);
        let anchored = pat_no_trailing_slash.contains('/');
        let pat_clean = pat_no_trailing_slash.strip_prefix('/').unwrap_or(pat_no_trailing_slash);
        if let Ok(matcher) = compile_rule_matcher(pat_clean, anchored) {
            rules.push(CompiledRule {
                negated: false,
                dir_only,
                matcher,
            });
        }
    }
    rules
}

/// A stack of `.gitignore` layers evaluated from root to leaf, plus explicit rules.
#[derive(Debug, Clone, Default)]
pub struct IgnoreStack {
    layers: Vec<RuleLayer>,
    explicit: Vec<CompiledRule>,
}

impl IgnoreStack {
    /// Creates a new [`IgnoreStack`] with pre-compiled explicit rules.
    pub fn new(explicit_patterns: &[NixIgnorePattern]) -> Self {
        Self {
            layers: Vec::new(),
            explicit: compile_explicit_ignore(explicit_patterns),
        }
    }

    /// Pushes a `.gitignore` layer onto the stack.
    pub fn push_layer(&mut self, layer: RuleLayer) {
        self.layers.push(layer);
    }

    /// Truncates the stack of `.gitignore` layers back to `saved_len`.
    pub fn truncate(&mut self, saved_len: usize) {
        self.layers.truncate(saved_len);
    }

    /// The current number of `.gitignore` layers on the stack.
    pub fn layer_count(&self) -> usize {
        self.layers.len()
    }

    /// Evaluates whether an entry at `rel_from_root` is ignored.
    pub fn is_ignored(&self, rel_from_root: &Path, file_name: &str, is_dir: bool) -> bool {
        // 1. Always ignore VCS metadata directories and worktree pointer files.
        if matches!(file_name, ".git" | ".jj" | ".hg") {
            return true;
        }

        let mut ignored = false;

        // 2. Evaluate `.gitignore` layers from target root down to leaf directory.
        for layer in &self.layers {
            let rel_in_layer = if layer.base_rel.as_os_str().is_empty() {
                Some(rel_from_root)
            } else {
                rel_from_root.strip_prefix(&layer.base_rel).ok()
            };

            let Some(rel_in_layer) = rel_in_layer else {
                continue;
            };

            let rel_str = rel_in_layer.to_str();

            for rule in &layer.rules {
                if rule.dir_only && !is_dir {
                    continue;
                }
                let is_match = match &rule.matcher {
                    RuleMatcher::All => true,
                    RuleMatcher::Basename(m) => m.is_match(file_name),
                    RuleMatcher::Anchored(m) => {
                        rel_str.is_some_and(|s| m.is_match(s))
                    }
                };
                if is_match {
                    ignored = !rule.negated;
                }
            }
        }

        // 3. Evaluate explicit rules from `provider.ignore` (anchored at root, cannot be negated).
        let rel_str = rel_from_root.to_str();
        for rule in &self.explicit {
            if rule.dir_only && !is_dir {
                continue;
            }
            let is_match = match &rule.matcher {
                RuleMatcher::All => true,
                RuleMatcher::Basename(m) => m.is_match(file_name),
                RuleMatcher::Anchored(m) => rel_str.is_some_and(|s| m.is_match(s)),
            };
            if is_match {
                return true;
            }
        }

        // 4. Return result from `.gitignore` layers.
        ignored
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vcs_metadata_is_always_ignored() {
        let stack = IgnoreStack::default();
        assert!(stack.is_ignored(Path::new(".git"), ".git", true));
        assert!(stack.is_ignored(Path::new(".git"), ".git", false));
        assert!(stack.is_ignored(Path::new(".jj"), ".jj", true));
        assert!(stack.is_ignored(Path::new(".jj"), ".jj", false));
        assert!(stack.is_ignored(Path::new(".hg"), ".hg", true));
        assert!(stack.is_ignored(Path::new(".hg"), ".hg", false));
        assert!(stack.is_ignored(Path::new("sub/.git"), ".git", true));
        assert!(stack.is_ignored(Path::new("sub/.git"), ".git", false));
        assert!(!stack.is_ignored(Path::new("flake.nix"), "flake.nix", false));
    }

    #[test]
    fn comments_escapes_trailing_spaces_and_crlf() {
        let content = "# This is a comment\r\n\
                       \r\n\
                       *.log   \r\n\
                       dir_with_space\\ \r\n\
                       \\#escaped_hash\r\n\
                       \\!escaped_bang\r\n";
        let layer = RuleLayer::from_gitignore_bytes(Path::new(""), content);
        assert_eq!(layer.rules.len(), 4);

        let mut stack = IgnoreStack::default();
        stack.push_layer(layer);

        // *.log matches any .log file
        assert!(stack.is_ignored(Path::new("app.log"), "app.log", false));
        // dir_with_space\  matches literal space
        assert!(stack.is_ignored(Path::new("dir_with_space "), "dir_with_space ", false));
        assert!(!stack.is_ignored(Path::new("dir_with_space"), "dir_with_space", false));
        // \#escaped_hash matches #escaped_hash
        assert!(stack.is_ignored(Path::new("#escaped_hash"), "#escaped_hash", false));
        // \!escaped_bang matches !escaped_bang
        assert!(stack.is_ignored(Path::new("!escaped_bang"), "!escaped_bang", false));
    }

    #[test]
    fn unanchored_vs_anchored_rules() {
        let content = "buck-out/\n\
                       /root-only\n\
                       sub/dir\n\
                       gen/**\n\
                       a/**/b\n";
        let layer = RuleLayer::from_gitignore_bytes(Path::new(""), content);
        let mut stack = IgnoreStack::default();
        stack.push_layer(layer);

        // buck-out/ is unanchored directory only
        assert!(stack.is_ignored(Path::new("buck-out"), "buck-out", true));
        assert!(!stack.is_ignored(Path::new("buck-out"), "buck-out", false));
        assert!(stack.is_ignored(Path::new("nested/buck-out"), "buck-out", true));
        assert!(!stack.is_ignored(Path::new("nested/buck-out"), "buck-out", false));

        // /root-only is anchored to root
        assert!(stack.is_ignored(Path::new("root-only"), "root-only", false));
        assert!(!stack.is_ignored(Path::new("sub/root-only"), "root-only", false));

        // sub/dir is anchored to root
        assert!(stack.is_ignored(Path::new("sub/dir"), "dir", false));
        assert!(!stack.is_ignored(Path::new("other/sub/dir"), "dir", false));

        // gen/** matches inside gen/
        assert!(!stack.is_ignored(Path::new("gen"), "gen", true));
        assert!(stack.is_ignored(Path::new("gen/out.nix"), "out.nix", false));
        assert!(stack.is_ignored(Path::new("gen/sub/out.nix"), "out.nix", false));

        // a/**/b matches a/b and a/x/b and a/x/y/b
        assert!(stack.is_ignored(Path::new("a/b"), "b", false));
        assert!(stack.is_ignored(Path::new("a/x/b"), "b", false));
        assert!(stack.is_ignored(Path::new("a/x/y/b"), "b", false));
        assert!(!stack.is_ignored(Path::new("other/a/b"), "b", false));
    }

    #[test]
    fn negation_layer_override_and_explicit_ignore_precedence() {
        let root_gi = "*.log\n!important.log\nbuild/\n";
        let sub_gi = "!special.log\nimportant.log\n";
        let explicit: Vec<NixIgnorePattern> = vec!["special.log".parse().unwrap()];

        let mut stack = IgnoreStack::new(&explicit);
        stack.push_layer(RuleLayer::from_gitignore_bytes(Path::new(""), root_gi));

        // In root:
        // regular.log is ignored
        assert!(stack.is_ignored(Path::new("regular.log"), "regular.log", false));
        // !important.log is un-ignored
        assert!(!stack.is_ignored(Path::new("important.log"), "important.log", false));

        // Now push sub/.gitignore layer
        let saved_len = stack.layer_count();
        stack.push_layer(RuleLayer::from_gitignore_bytes(Path::new("sub"), sub_gi));

        // Inside sub:
        // regular.log is still ignored from root layer
        assert!(stack.is_ignored(Path::new("sub/regular.log"), "regular.log", false));
        // important.log is re-ignored by sub/.gitignore
        assert!(stack.is_ignored(Path::new("sub/important.log"), "important.log", false));
        // special.log has !special.log in sub/.gitignore, BUT explicit ignore says special.log!
        // Explicit ignore wins over .gitignore negation!
        assert!(stack.is_ignored(Path::new("sub/special.log"), "special.log", false));
        assert!(stack.is_ignored(Path::new("special.log"), "special.log", false));

        // Truncate back to root layer
        stack.truncate(saved_len);
        assert_eq!(stack.layer_count(), 1);
        // Under sub now, important.log is un-ignored again (as seen by root layer only)
        assert!(!stack.is_ignored(Path::new("sub/important.log"), "important.log", false));
    }
}
