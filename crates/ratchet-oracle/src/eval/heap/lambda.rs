//! Constructors and accessors for [`EvalLambda`] closure records.

use super::*;

impl EvalLambda {
    /// Returns whether two payload snapshots retain the same closure backing.
    pub(crate) fn raw_eq(&self, other: &Self) -> bool {
        self.module == other.module
            && self.pattern == other.pattern
            && self.body == other.body
            && self.frame == other.frame
            && self.env.raw_eq(&other.env)
            && self.with_env.raw_eq(&other.with_env)
            && self.scoped_globals.raw_eq(&other.scoped_globals)
    }

    /// Creates a lambda closure record.
    pub fn new(pattern: IrId, body: IrId, frame: FrameId, env: EvalEnv) -> Self {
        Self::with_captures(
            EvalModuleId::ROOT,
            pattern,
            body,
            frame,
            env,
            EvalWithEnv::default(),
            EvalScopedGlobalEnv::default(),
        )
    }

    /// Creates a lambda closure record with lexical and dynamic captures.
    pub fn with_captures(
        module: EvalModuleId,
        pattern: IrId,
        body: IrId,
        frame: FrameId,
        env: EvalEnv,
        with_env: EvalWithEnv,
        scoped_globals: EvalScopedGlobalEnv,
    ) -> Self {
        Self {
            module,
            pattern,
            body,
            frame,
            env,
            with_env,
            scoped_globals,
        }
    }

    /// Returns the module that owns this lambda's lowered pattern and body.
    pub const fn module(&self) -> EvalModuleId {
        self.module
    }

    /// Returns the lowered parameter pattern.
    pub const fn pattern(&self) -> IrId {
        self.pattern
    }

    /// Returns the lowered body expression.
    pub const fn body(&self) -> IrId {
        self.body
    }

    /// Returns the resolver frame associated with this lambda.
    pub const fn frame(&self) -> FrameId {
        self.frame
    }

    /// Returns the lexical environment captured when this lambda was allocated.
    pub const fn env(&self) -> &EvalEnv {
        &self.env
    }

    /// Replaces the lexical environment before the closure is published.
    pub(crate) fn replace_env(&mut self, env: EvalEnv) {
        self.env = env;
    }

    /// Returns the dynamic `with` environment captured when this lambda was allocated.
    pub const fn with_scope_env(&self) -> &EvalWithEnv {
        &self.with_env
    }

    /// Returns the scoped-import global environment captured when this lambda was allocated.
    pub const fn scoped_global_env(&self) -> &EvalScopedGlobalEnv {
        &self.scoped_globals
    }
}
