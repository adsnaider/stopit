//! The `config` provider: a manifest written inline (DESIGN.md §3.6).

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use super::{Provider, ProviderContext, ProviderError, ProviderOutput};
use crate::config::{ProfileRef, ProviderName, ProviderOrigin};
use crate::manifest::Manifest;

/// Returns the inline `[provider.sandbox]` manifest, resolving any proxy shim
/// paths against its configuration directory and `ctx`.
#[derive(Debug, Clone)]
pub struct ConfigProvider {
    name: ProviderName,
    profile: ProfileRef,
    manifest: Manifest,
    base_dir: PathBuf,
    protected_proxies: OnceLock<Vec<PathBuf>>,
    origin: ProviderOrigin,
}

impl ConfigProvider {
    /// Creates a workspace-origin provider applying `manifest` to `profile`.
    pub fn new(name: ProviderName, profile: ProfileRef, manifest: Manifest) -> Self {
        Self::with_origin(name, profile, manifest, ProviderOrigin::Workspace)
    }

    /// Creates a provider applying `manifest` to `profile` tagged with
    /// `origin`.
    pub fn with_origin(
        name: ProviderName,
        profile: ProfileRef,
        manifest: Manifest,
        origin: ProviderOrigin,
    ) -> Self {
        Self::with_base_dir(name, profile, manifest, Path::new(""), origin)
    }

    /// Creates a provider applying `manifest` to `profile` declared in
    /// `base_dir` and tagged with `origin`.
    pub fn with_base_dir(
        name: ProviderName,
        profile: ProfileRef,
        manifest: Manifest,
        base_dir: &Path,
        origin: ProviderOrigin,
    ) -> Self {
        ConfigProvider {
            name,
            profile,
            manifest,
            base_dir: base_dir.to_owned(),
            protected_proxies: OnceLock::new(),
            origin,
        }
    }
}

impl Provider for ConfigProvider {
    fn name(&self) -> &ProviderName {
        &self.name
    }

    fn manifest(&self, ctx: &ProviderContext) -> Result<ProviderOutput, ProviderError> {
        let mut manifest = self.manifest.clone();
        let protected =
            super::resolve_manifest_proxies(&self.name, &self.base_dir, &mut manifest, ctx)?;
        let _ = self.protected_proxies.set(protected);
        Ok(ProviderOutput {
            profile: self.profile.clone(),
            manifest,
            origin: self.origin,
        })
    }

    fn protected_paths(&self) -> Result<Vec<PathBuf>, ProviderError> {
        if let Some(paths) = self.protected_proxies.get() {
            return Ok(paths.clone());
        }
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_default();
        let mut out = Vec::new();
        let shims = self.manifest.grants.shims.values().chain(
            self.manifest
                .profiles
                .values()
                .flat_map(|p| p.grants.shims.values()),
        );
        for spec in shims {
            if let crate::manifest::ShimKind::Proxy {
                proxy,
                protect: true,
                ..
            } = &spec.kind
            {
                let declared = proxy.expand(&self.base_dir, &home);
                let canonical = std::fs::canonicalize(&declared).map_err(|error| {
                    super::base_dir_error(&self.name, &declared, &self.base_dir).unwrap_or_else(
                        || ProviderError::Resolve {
                            name: self.name.clone(),
                            script: declared,
                            error,
                        },
                    )
                })?;
                if !out.contains(&canonical) {
                    out.push(canonical);
                }
            }
        }
        Ok(out)
    }

    /// The inline manifest, as [`manifest`](Provider::manifest) returns it.
    fn static_output(&self) -> Option<ProviderOutput> {
        Some(ProviderOutput {
            profile: self.profile.clone(),
            manifest: self.manifest.clone(),
            origin: self.origin,
        })
    }
}
