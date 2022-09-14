// Copyright 2022 LEXUGE
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

mod message;
mod utils;

use self::message::{DnsRecordsIter, OptRecordsIter};
use crate::{Upstreams, Validatable};
use bytes::Bytes;
use domain::base::Message;
use rhai::{
    def_package,
    packages::{Package, StandardPackage},
    plugin::*,
    set_exported_global_fn, Engine, Scope, AST,
};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use thiserror::Error;

type Result<T> = std::result::Result<T, ScriptError>;

/// Errors generated by the `script` module.
#[derive(Error, Debug)]
pub enum ScriptError {
    /// Buf is too short
    #[error(transparent)]
    ShortBuf(#[from] domain::base::ShortBuf),

    /// Error forwarded from `Upstreams`
    #[error(transparent)]
    UpstreamError(#[from] crate::error::UpstreamError),

    /// Rhai Eval Error,
    #[error(transparent)]
    RhaiEvalError(#[from] Box<rhai::plugin::EvalAltResult>),

    /// Rhai Parse Error,
    #[error(transparent)]
    RhaiParseError(#[from] rhai::ParseError),
}

#[rustfmt::skip]
def_package! {
    pub RoutePackage(module) {
	InitPackage::init(module);

	module.set_iterable::<DnsRecordsIter>();
	module.set_iterable::<OptRecordsIter>();

	combine_with_exported_module!(module, "message", self::message::rhai_mod);
	set_exported_global_fn!(module, "send", super::upstreams::send);
	set_exported_global_fn!(module, "send", super::upstreams::send_default);
    }

    // Only modules from utils should be imported here
    pub InitPackage(module) {
	StandardPackage::init(module);

	combine_with_exported_module!(module, "utils", self::utils::rhai_mod);
    }
}

/// The script engine used to evaluate the route script
pub struct Script {
    // Per doc: Currently the lifetime parameter is not used, but it is not guaranteed to remain unused for future versions. Until then, 'static can be used.
    scope: Scope<'static>,
    route_package: RoutePackage,
    ast: AST,
}

/// Query Context
#[derive(Clone)]
pub struct QueryContext {
    /// Query sender's IP address
    pub ip: IpAddr,
}

impl Script {
    /// Process the given query and context with predefined route script
    pub fn route(
        &self,
        query: Message<Bytes>,
        ctx: Option<QueryContext>,
    ) -> Result<Message<Bytes>> {
        let mut engine = Engine::new_raw();
        engine
            .register_global_module(self.route_package.as_shared_module())
            .on_print(|x| log::info!("{}", x))
            .on_debug(|x, src, pos| log::debug!("{} at {}: {}", x, src.unwrap_or("unkown"), pos));

        // Then turn it into an immutable instance
        let engine = engine;

        let mut scope = self.scope.clone();

        scope.push_constant("query", query);
        scope.push_constant("ctx", ctx);

        Ok(engine.eval_ast_with_scope::<Message<Bytes>>(&mut scope, &self.ast)?)
    }
}

impl Validatable for Script {
    type Error = ScriptError;

    fn validate(&self, _: Option<&Vec<crate::Label>>) -> Result<()> {
        // Guaranteed to exist as we pushed it in on creation.
        let upstreams = self.scope.get_value::<Upstreams>("upstreams").unwrap();
        upstreams.validate(None)?;
        Ok(())
    }
}

/// The builder for `Script`
#[derive(Serialize, Deserialize, Clone)]
pub struct ScriptBuilder {
    init: Option<String>,
    route: String,
}

impl ScriptBuilder {
    /// Create a script builder with init and route script
    pub fn new<T: ToString>(init: Option<T>, route: T) -> Self {
        Self {
            init: init.map(|s| s.to_string()),
            route: route.to_string(),
        }
    }

    /// Build `Script` with upstreams
    pub fn build(&self, upstreams: Upstreams) -> Result<Script> {
        // Register functions here
        let mut scope = Scope::new();

        let init_package = InitPackage::new();

        let mut engine = Engine::new_raw();
        engine
            .register_global_module(init_package.as_shared_module())
            .on_print(|x| log::info!("{}", x))
            .on_debug(|x, src, pos| log::debug!("{} at {}: {}", x, src.unwrap_or("unkown"), pos));

        // Then turn it into an immutable instance
        let engine = engine;

        let ast = engine.compile(&self.route)?;

        if let Some(init) = &self.init {
            // Initialize scope without Upstreams
            engine.run_with_scope(&mut scope, init)?;
        }

        // Push Upstreams
        scope.push_constant("upstreams", upstreams);

        Ok(Script {
            scope,
            ast,
            route_package: RoutePackage::new(),
        })
    }
}
