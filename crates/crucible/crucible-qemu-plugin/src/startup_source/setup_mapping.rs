//! Retains the authentic Source-created setup VMA and its canonical transfer.
//!
//! The permissive view exposes wire access only. Native owns creation, permanent
//! DONTFORK disposition and sole physical return. Before transfer, the caller
//! field is a movable projection of Source's own canonical field; after transfer,
//! the destination stays in the prepaid pinned Runtime through every last use.
// SPDX-License-Identifier: GPL-2.0-only

use std::ffi::c_void;

use crucible_qemu_shmem::{MappedSetupView, SetupRegionBackingIdentity};

use super::{InstallerStartupSource, StartupSourceError, runtime_purpose::RuntimePurpose};

/// Names the genuine Source-owned VMA, without nominating address geometry.
#[repr(C)]
pub(super) struct NativeMapping {
    _private: [u8; 0],
}

type Create = extern "C" fn(u64, *mut *mut NativeMapping, *mut *mut c_void, *mut usize) -> i32;
type Transfer = extern "C" fn(
    u64,
    *mut RuntimePurpose,
    *mut *mut NativeMapping,
    *mut *mut NativeMapping,
) -> i32;
type Current = extern "C" fn(u64, *mut NativeMapping) -> i32;
type IdentityReturn = extern "C" fn(u64, *mut *mut NativeMapping) -> i32;

#[derive(Clone, Copy)]
struct Api {
    create: Create,
    transfer: Transfer,
    current: Current,
    identity_return: IdentityReturn,
}

/// Inline mapping custody; its entire body is included in configured Runtime row0.
///
/// The containing inline mutex serializes installer and manual FFI callback
/// access. Each try-lock refuses overlap or poison without releasing custody.
/// Native's four methods never invoke a module callback; the explicit Rust
/// installing checks run outside this mutex. The canonical field never moves
/// after transfer, including during lock acquisition or guard destruction.
#[derive(Default)]
pub(super) struct SetupMapping {
    api: Option<Api>,
    projection: *mut NativeMapping,
    holder: *mut NativeMapping,
    address: *mut c_void,
    bytes: usize,
    attempted: bool,
    transfer_attempted: bool,
}

impl SetupMapping {
    // These actual field writes and effects are shared with negative-output
    // controls; the controls provide no accepting Source or native authority.
    fn create_using(&mut self, api: Api, plugin_id: u64) -> i32 {
        self.api = Some(api);
        self.attempted = true;
        (api.create)(
            plugin_id,
            &mut self.projection,
            &mut self.address,
            &mut self.bytes,
        )
    }

    fn transfer_using(&mut self, api: Api, plugin_id: u64, runtime: *mut RuntimePurpose) -> i32 {
        self.transfer_attempted = true;
        (api.transfer)(plugin_id, runtime, &mut self.projection, &mut self.holder)
    }
}

impl InstallerStartupSource {
    /// Creates the real authenticated setup-role mapping without nominating a span.
    ///
    /// # Errors
    /// Refuses missing exports, repeated use, native construction/post failures,
    /// or inconsistent view geometry. Every born output remains in this Source.
    pub(crate) fn create_setup_mapping(
        &self,
        expected: SetupRegionBackingIdentity,
    ) -> Result<MappedSetupView, crate::PluginSetupError> {
        self.check().map_err(source_error)?;
        let api = resolve().map_err(source_error)?;
        let mut mapping = self.setup_mapping.try_lock().map_err(|_| {
            source_error(StartupSourceError::Ownership {
                reason: "setup mapping custody is busy or poisoned",
            })
        })?;
        if mapping.attempted {
            return Err(source_error(StartupSourceError::Ownership {
                reason: "setup mapping creation cannot be repeated",
            }));
        }
        let result = mapping.create_using(api, self.plugin_id);
        drop(mapping);
        let post = self.check();
        if result != 0 {
            return Err(source_error(StartupSourceError::NativeStatus {
                status: result,
            }));
        }
        post.map_err(source_error)?;
        let mapping = self.setup_mapping.try_lock().map_err(|_| {
            source_error(StartupSourceError::Ownership {
                reason: "setup mapping custody is busy or poisoned",
            })
        })?;
        if mapping.projection.is_null()
            || mapping.address.is_null()
            || u64::try_from(mapping.bytes).ok() != Some(expected.length())
        {
            return Err(source_error(StartupSourceError::Ownership {
                reason: "native setup mapping returned inconsistent retained outputs",
            }));
        }
        // Slot creation retains this genuine Source projection, not the wire
        // view's address or a caller-selected ordinal. Neither owner has moved.
        self.create_setup_slot(mapping.projection)
            .map_err(source_error)?;
        // SAFETY: the authentic constructor retains this complete writable VMA
        // in Source independently of the movable projection. The installer
        // keeps Source and then its pinned Runtime while every view is used.
        unsafe {
            MappedSetupView::from_retained_mapping(
                mapping.address.cast(),
                expected.length(),
                expected,
            )
        }
        .map_err(|source| crate::PluginSetupError::MapRegion { source })
    }

    /// Transfers creation custody into the same field of the already pinned Runtime.
    ///
    /// # Safety
    /// The containing Runtime has been prepaid and pinned before completion
    /// enrollment. It and this destination field must never move or be freed
    /// until Native consumes the canonical field through actual physical return.
    ///
    /// # Errors
    /// Refuses absent/repeated custody or the authentic completion/transfer cut.
    /// A negative post can follow a real move and retains the destination field.
    pub(crate) unsafe fn transfer_setup_mapping(&self) -> Result<(), StartupSourceError> {
        self.check_runtime_installation()?;
        let runtime = self.setup_mapping_runtime_purpose()?;
        let mut mapping =
            self.setup_mapping
                .try_lock()
                .map_err(|_| StartupSourceError::Ownership {
                    reason: "setup mapping custody is busy or poisoned",
                })?;
        // Explicit owning model mappings have no native custody to transfer.
        #[cfg(test)]
        if self.model_setup.is_some() && !mapping.attempted {
            return Ok(());
        }
        if mapping.projection.is_null() || mapping.transfer_attempted {
            return Err(StartupSourceError::Ownership {
                reason: "setup mapping transfer has no unused creating projection",
            });
        }
        let api = mapping.api.ok_or(StartupSourceError::Ownership {
            reason: "setup mapping API was not retained",
        })?;
        let result = mapping.transfer_using(api, self.plugin_id, runtime);
        drop(mapping);
        let post = self.check_runtime_installation();
        // Both fields already contain Native's actual disposition even when the
        // independent post refused. Do not restore or manufacture either field.
        if result != 0 {
            return Err(StartupSourceError::NativeStatus { status: result });
        }
        post?;
        let mapping = self
            .setup_mapping
            .try_lock()
            .map_err(|_| StartupSourceError::Ownership {
                reason: "setup mapping custody is busy or poisoned",
            })?;
        if mapping.holder.is_null() || !mapping.projection.is_null() {
            return Err(StartupSourceError::Ownership {
                reason: "native setup mapping did not complete canonical transfer",
            });
        }
        drop(mapping);
        // SAFETY: the same caller pinning contract covers both inline destinations.
        unsafe { self.transfer_setup_exchange() }
    }

    /// Corroborates retained Native DONTFORK custody without changing the VMA.
    ///
    /// # Errors
    /// Refuses absent, foreign or retired native custody. No clock is queried.
    pub(crate) fn check_setup_mapping(&self) -> Result<(), StartupSourceError> {
        let mapping = self
            .setup_mapping
            .try_lock()
            .map_err(|_| StartupSourceError::Ownership {
                reason: "setup mapping custody is busy or poisoned",
            })?;
        let owner = if mapping.holder.is_null() {
            mapping.projection
        } else {
            mapping.holder
        };
        let api = mapping.api.ok_or(StartupSourceError::Ownership {
            reason: "setup mapping API was not retained",
        })?;
        if owner.is_null() {
            return Err(StartupSourceError::Ownership {
                reason: "setup mapping custody is absent",
            });
        }
        let status = (api.current)(self.plugin_id, owner);
        if status == 0 {
            Ok(())
        } else {
            Err(StartupSourceError::NativeStatus { status })
        }
    }

    /// Attempts pure physical return only after the caller has ended every view use.
    ///
    /// # Safety
    /// No view, callback, worker or detached wire handle may be accessed again if
    /// this returns true. The pinned Runtime field remains live on refusal.
    pub(crate) unsafe fn return_setup_mapping(&self) -> bool {
        // SAFETY: the caller's complete last-use contract applies to the slot
        // and its retained exchange before the VMA parent can retire.
        if !unsafe { self.return_setup_exchange() } {
            return false;
        }
        let Ok(mut mapping) = self.setup_mapping.try_lock() else {
            return false;
        };
        let Some(api) = mapping.api else {
            return !mapping.attempted;
        };
        let field = if mapping.holder.is_null() {
            &mut mapping.projection
        } else {
            &mut mapping.holder
        };
        if field.is_null() {
            return true;
        }
        let status = (api.identity_return)(self.plugin_id, field);
        // A signed refusal never permits deallocation of a live canonical field.
        status == 0 && mapping.holder.is_null() && mapping.projection.is_null()
    }
}

fn source_error(source: StartupSourceError) -> crate::PluginSetupError {
    crate::PluginSetupError::StartupSource { source }
}

fn resolve() -> Result<Api, StartupSourceError> {
    macro_rules! resolve {
        ($name:literal, $signature:ty) => {{
            // SAFETY: the immutable matched annotated SDK exports this exact C
            // signature. Symbol resolution itself provides no owning authority.
            let symbol = unsafe { libc::dlsym(libc::RTLD_DEFAULT, $name.as_ptr()) };
            if symbol.is_null() {
                return Err(StartupSourceError::Unavailable {
                    symbol: $name.to_str().map_err(|_| StartupSourceError::Ownership {
                        reason: "required mapping symbol is not ASCII",
                    })?,
                });
            }
            // SAFETY: the matched provider implements the literal SDK signature.
            unsafe { std::mem::transmute::<*mut c_void, $signature>(symbol) }
        }};
    }
    Ok(Api {
        create: resolve!(
            c"qemu_plugin_crucible_startup_setup_mapping_create_v1",
            Create
        ),
        transfer: resolve!(
            c"qemu_plugin_crucible_startup_setup_mapping_transfer_v1",
            Transfer
        ),
        current: resolve!(
            c"qemu_plugin_crucible_startup_setup_mapping_current_v1",
            Current
        ),
        identity_return: resolve!(
            c"qemu_plugin_crucible_startup_setup_mapping_return_v1",
            IdentityReturn
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    extern "C" fn born_negative(
        _id: u64,
        owner: *mut *mut NativeMapping,
        address: *mut *mut c_void,
        bytes: *mut usize,
    ) -> i32 {
        // SAFETY: the actual calling helper supplies exclusive live output fields.
        // Dangling values model retained negative outputs and are never accessed.
        unsafe {
            *owner = std::ptr::dangling_mut();
            *address = std::ptr::dangling_mut();
            *bytes = 8192;
        }
        -libc::ECANCELED
    }

    extern "C" fn moved_negative(
        _id: u64,
        _runtime: *mut RuntimePurpose,
        from: *mut *mut NativeMapping,
        to: *mut *mut NativeMapping,
    ) -> i32 {
        // SAFETY: the helper supplies distinct exclusive fields; no fake pointer
        // is dereferenced or enrolled as an accepting native Runtime.
        unsafe {
            *to = *from;
            *from = std::ptr::null_mut();
        }
        -libc::ETIMEDOUT
    }

    extern "C" fn refusing_current(_id: u64, _owner: *mut NativeMapping) -> i32 {
        -libc::ENOENT
    }

    extern "C" fn refusing_return(_id: u64, _holder: *mut *mut NativeMapping) -> i32 {
        -libc::EBUSY
    }

    fn api() -> Api {
        Api {
            create: born_negative,
            transfer: moved_negative,
            current: refusing_current,
            identity_return: refusing_return,
        }
    }

    #[test]
    fn born_negative_keeps_all_creation_outputs_before_status() {
        let mut custody = SetupMapping::default();
        let status = custody.create_using(api(), 7);

        assert_eq!(status, -libc::ECANCELED);
        assert!(custody.attempted);
        assert!(!custody.projection.is_null());
        assert!(!custody.address.is_null());
        assert_eq!(custody.bytes, 8192);
        assert!(custody.holder.is_null());
    }

    #[test]
    fn negative_transfer_keeps_destination_and_consumed_projection() {
        let mut custody = SetupMapping::default();
        let _birth = custody.create_using(api(), 7);
        let created = custody.projection;
        let status = custody.transfer_using(api(), 7, std::ptr::null_mut());

        assert_eq!(status, -libc::ETIMEDOUT);
        assert!(custody.transfer_attempted);
        assert!(custody.projection.is_null());
        assert_eq!(custody.holder, created);
        assert_eq!(
            (api().identity_return)(7, &mut custody.holder),
            -libc::EBUSY
        );
        assert_eq!(custody.holder, created);
    }
}
