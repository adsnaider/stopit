//! Resolution of the providers' outputs into per-profile sandboxes
//! (DESIGN.md §3.3, §3.5, §3.6).
//!
//! First the structure is resolved: which profiles exist, what they inherit
//! from, and which grants each provider contributes to each of them
//! ([`build_profile_graph`]). Then every grant section except the path
//! rules is merged into each profile's effective grants
//! ([`merge_profiles`]). Finally path precedence turns a profile's path
//! rules into a mount plan ([`plan_mounts`]).

mod graph;
mod merge;
mod paths;

pub use graph::{
    Contribution, ProfileError, ProfileGraph, ProfileNode, ShimField, build_profile_graph,
};
pub use merge::{
    EffectiveEnv, EffectiveGrants, EffectiveNetwork, EffectiveSandbox, EffectiveSystem,
    EnvSetConflict, FsRule, FsRuleKind, MergeError, MergedProfiles, merge_profiles,
};
pub use paths::{
    MountConflict, MountPlan, MountSource, PathPlanError, PlanWarning, PlanWarningKind,
    PlannedMount, plan_mounts,
};
