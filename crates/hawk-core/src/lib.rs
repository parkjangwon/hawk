//! Core domain and analysis functionality for Hawk.

pub mod ast;
pub mod baseline;
pub mod cache;
pub(crate) mod code_graph;
pub mod config;
pub mod discovery;
pub mod finding;
pub mod fixture;
pub mod git;
pub mod language;
pub mod pack;
mod pack_load;
mod pack_query;
pub mod parser;
pub mod report;
pub mod reporter;
pub mod scan;
pub mod scope;
pub mod semantic;
pub mod suppress;
pub mod taint;
mod taint_engine;
