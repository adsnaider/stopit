//! The `config` provider: a manifest written inline (DESIGN.md §3.6).

use super::{Provider, ProviderContext, ProviderError, ProviderOutput};
use crate::config::{ProfileRef, ProviderName};
use crate::manifest::Manifest;

/// Returns the inline `[provider.sandbox]` manifest unchanged.
#[derive(Debug, Clone)]
pub struct ConfigProvider {
    name: ProviderName,
    profile: ProfileRef,
    manifest: Manifest,
}

impl ConfigProvider {
    /// Creates a provider applying `manifest` to `profile`.
    pub fn new(name: ProviderName, profile: ProfileRef, manifest: Manifest) -> Self {
        ConfigProvider {
            name,
            profile,
            manifest,
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
        })
    }

    /// The inline manifest, as [`manifest`](Provider::manifest) returns it.
    fn static_output(&self) -> Option<ProviderOutput> {
        Some(ProviderOutput {
            profile: self.profile.clone(),
            manifest: self.manifest.clone(),
        })
    }
}
