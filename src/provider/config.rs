//! The `config` provider: a manifest written inline (DESIGN.md §3.6).

use super::{Provider, ProviderContext, ProviderError, ProviderOutput};
use crate::config::{ProfileRef, ProviderName, ProviderOrigin};
use crate::manifest::Manifest;

/// Returns the inline `[provider.sandbox]` manifest unchanged.
#[derive(Debug, Clone)]
pub struct ConfigProvider {
    name: ProviderName,
    profile: ProfileRef,
    manifest: Manifest,
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
        ConfigProvider {
            name,
            profile,
            manifest,
            origin,
        }
    }
}

impl Provider for ConfigProvider {
    fn name(&self) -> &ProviderName {
        &self.name
    }

    /// Ignores the context: an inline manifest does not depend on the host.
    fn manifest(&self, _ctx: &ProviderContext) -> Result<ProviderOutput, ProviderError> {
        Ok(ProviderOutput {
            profile: self.profile.clone(),
            manifest: self.manifest.clone(),
            origin: self.origin,
        })
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
