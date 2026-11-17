//! Behavior detection engine and rules.

pub mod engine;
pub mod rule;

pub use engine::BehaviorEngine;
pub use rule::{BehaviorRule, DetectionMatch};
