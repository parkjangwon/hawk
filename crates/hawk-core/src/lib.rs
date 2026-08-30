//! Core domain and analysis functionality for Hawk.

pub mod ast;
pub mod baseline;
pub mod cache;
pub mod code_graph;
pub mod config;
pub mod discovery;
pub mod finding;
pub mod fixture;
pub mod git;
pub mod language;
pub mod pack;
mod pack_load;
pub mod parser;
pub mod report;
pub mod reporter;
pub mod scan;
pub mod scope;
pub mod semantic;
pub mod taint;
mod taint_engine;
