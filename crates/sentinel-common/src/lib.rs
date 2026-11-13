//! sentinel-common — Shared types for the Sentinel-RS security daemon.
//!
//! This crate provides the common data structures used across all Sentinel-RS
//! components: eBPF event formats, process lineage nodes, risk scoring engine
//! types, IPC protocol messages, configuration models, and incident reports.

pub mod config;
pub mod events;
pub mod incident;
pub mod ipc;
pub mod process;
pub mod risk;
