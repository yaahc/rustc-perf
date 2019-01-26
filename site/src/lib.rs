// Copyright 2016 The rustc-perf Project Developers. See the COPYRIGHT
// file at the top-level directory.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

extern crate antidote;
extern crate chrono;
extern crate collector;
extern crate flate2;
extern crate futures;
extern crate futures_cpupool;
#[macro_use]
extern crate hyper;
#[macro_use]
extern crate log;
extern crate rust_sysroot;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate rmp_serde;
extern crate semver;
extern crate serde_json;
extern crate url;
#[macro_use]
extern crate failure;
extern crate hex;
extern crate regex;
extern crate ring;
#[macro_use]
extern crate lazy_static;
extern crate reqwest;
extern crate toml;
extern crate cache;

#[derive(Fail, Debug)]
#[fail(display = "command failed: {}", command)]
pub struct CommandFailed {
    command: String,
}

mod git;

pub mod api;
pub mod load;
pub mod server;
pub mod util;
