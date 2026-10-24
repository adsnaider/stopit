//! Resolution of the providers' outputs into per-profile sandboxes
//! (DESIGN.md §3.3, §3.5, §3.6).
//!
//! So far only the structure is resolved: which profiles exist, what they
//! inherit from, and which grants each provider contributes to each of them
//! ([`build_profile_graph`]). Merging grant contents happens later.

mod graph;

pub use graph::{
    Contribution, ProfileError, ProfileGraph, ProfileNode, ShimField, build_profile_graph,
};
