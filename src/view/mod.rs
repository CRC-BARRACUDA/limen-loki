//! Everything the module draws.
//!
//! A view is a JSON spec the host renders, so these are pure functions of what
//! is being shown — no state, no host calls — which is also why they are the
//! easy part to test.

mod install;
mod results;
mod scan;
mod signatures;
mod tab;

pub(crate) use install::*;
pub(crate) use results::*;
pub(crate) use scan::*;
pub(crate) use signatures::*;
pub(crate) use tab::*;
