//! Matches the retained native RAM actor and record operation SDK.
// SPDX-License-Identifier: GPL-2.0-or-later

use std::ffi::c_void;

pub(super) const WAIT_READ: u32 = 1;
pub(super) const WAIT_WRITE: u32 = 2;

#[repr(C)]
pub(super) struct Actor {
    _private: [u8; 0],
}

#[repr(C)]
pub(super) struct Receive {
    _private: [u8; 0],
}

#[repr(C)]
#[derive(Default)]
pub(super) struct Endpoint {
    pub schema_version: u32,
    pub struct_size: u32,
    pub purpose: *mut c_void,
    pub descriptor: i32,
    pub reserved: u32,
    pub session: *const u8,
    pub target_daemon: *const u8,
    pub target_owner: *const u8,
    pub target_node: *const u8,
    pub owner_generation: u64,
    pub arena_generation: u64,
    pub template: u32,
    pub reserved2: u32,
}

#[repr(C)]
#[derive(Default)]
pub(super) struct Borrow {
    pub schema_version: u32,
    pub struct_size: u32,
    pub loan: *mut Receive,
    pub frame: *const u8,
    pub frame_capacity: usize,
}

#[repr(C)]
#[derive(Default)]
pub(super) struct EndStatus {
    pub terminal_journal: u32,
    pub completion_result: i32,
}

#[repr(C)]
#[derive(Default)]
pub(super) struct ActorStatus {
    pub schema_version: u32,
    pub struct_size: u32,
    pub born: u32,
    pub returned: u32,
    pub joined: u32,
    pub join_attempted: u32,
    pub join_result: i32,
    pub join_errno: i32,
    pub entry_status: i32,
    pub first_status: i32,
    pub post_status: i32,
}

#[repr(C)]
#[derive(Default)]
pub(super) struct TerminalStatus {
    pub schema_version: u32,
    pub struct_size: u32,
    pub arm_request_digest: [u8; 32],
    pub request_generation: u64,
    pub connection_epoch: u64,
    pub physical_state: u32,
    pub first_status: i32,
    pub post_status: i32,
    pub reserved: u32,
}

pub(super) type Entry = extern "C" fn(u64, *mut Actor, i32, *mut c_void) -> i32;
pub(super) type Acquire =
    extern "C" fn(u64, *mut Actor, *mut Receive, *mut c_void, *mut *mut c_void) -> i32;
pub(super) type Query =
    extern "C" fn(u64, *mut Actor, *mut Receive, *mut c_void, *mut c_void, *mut u64) -> i32;
pub(super) type End =
    extern "C" fn(u64, *mut Actor, *mut Receive, *mut c_void, *mut c_void, *mut EndStatus) -> i32;
pub(super) type Release =
    extern "C" fn(u64, *mut Actor, *mut Receive, *mut c_void, *mut c_void) -> i32;
type Register = extern "C" fn(
    u64,
    *mut c_void,
    *mut c_void,
    Option<Acquire>,
    Option<Query>,
    Option<End>,
    Option<Release>,
    *mut c_void,
) -> i32;
type Start =
    extern "C" fn(u64, *mut c_void, u64, Option<Entry>, *mut c_void, *mut *mut Actor) -> i32;
type EndpointBorrow = extern "C" fn(u64, *mut c_void, *mut Endpoint) -> i32;
type Begin = extern "C" fn(u64, *mut Actor, *mut Borrow) -> i32;
type Read = extern "C" fn(u64, *mut Actor, *mut Receive, usize, *mut usize) -> i32;
type DescriptorFree = extern "C" fn(u64, *mut Actor, *mut Receive) -> i32;
type Dispose = extern "C" fn(u64, *mut Actor, *mut Receive, i32) -> i32;
type Pending = extern "C" fn(u64, *mut Actor, *mut Receive, *const u8, *const u8, *mut u64) -> i32;
type Observe = extern "C" fn(u64, *mut Actor, *mut ActorStatus) -> i32;
type Terminal = extern "C" fn(u64, *mut Actor, *const u8, u64, u64, *mut TerminalStatus) -> i32;
type ActorAction = extern "C" fn(u64, *mut Actor) -> i32;
type Wait = extern "C" fn(u64, *mut Actor, u32) -> i32;

#[derive(Clone, Copy)]
pub(super) struct Api {
    pub register: Register,
    pub start: Start,
    pub endpoint: EndpointBorrow,
    pub begin: Begin,
    pub read: Read,
    pub descriptor_free: DescriptorFree,
    pub dispose: Dispose,
    pub record_return: Dispose,
    pub pending: Pending,
    pub terminal: Terminal,
    pub wait: Wait,
    pub dispatch_end: ActorAction,
    pub observe: Observe,
    pub quiesce: ActorAction,
    pub quiesce_join: ActorAction,
}

impl Api {
    pub(super) fn resolve() -> Result<Self, i32> {
        macro_rules! resolve {
            ($name:literal,$signature:ty) => {{
                // SAFETY: each static name and signature matches the complete
                // process-private native SDK; resolution lends no authority.
                let address = unsafe { libc::dlsym(libc::RTLD_DEFAULT, $name.as_ptr()) };
                if address.is_null() {
                    return Err(-libc::ENOSYS);
                }
                // SAFETY: the resolved function has the exact frozen declaration.
                unsafe { std::mem::transmute::<*mut c_void, $signature>(address) }
            }};
        }
        Ok(Self {
            register: resolve!(
                c"qemu_plugin_crucible_register_ram_control_record_v1",
                Register
            ),
            start: resolve!(c"qemu_plugin_crucible_ram_control_actor_start_v1", Start),
            endpoint: resolve!(
                c"qemu_plugin_crucible_startup_ram_endpoint_borrow_v1",
                EndpointBorrow
            ),
            begin: resolve!(c"qemu_plugin_crucible_ram_control_receive_begin_v1", Begin),
            read: resolve!(c"qemu_plugin_crucible_ram_control_receive_read_v1", Read),
            descriptor_free: resolve!(
                c"qemu_plugin_crucible_ram_control_receive_descriptor_free_v1",
                DescriptorFree
            ),
            dispose: resolve!(
                c"qemu_plugin_crucible_ram_control_receive_dispose_v1",
                Dispose
            ),
            record_return: resolve!(
                c"qemu_plugin_crucible_ram_control_record_return_v1",
                Dispose
            ),
            pending: resolve!(c"qemu_plugin_crucible_checkpoint_pending_adopt_v1", Pending),
            terminal: resolve!(
                c"qemu_plugin_crucible_checkpoint_terminal_observe_v1",
                Terminal
            ),
            wait: resolve!(c"qemu_plugin_crucible_ram_control_dispatch_wait_v2", Wait),
            dispatch_end: resolve!(
                c"qemu_plugin_crucible_ram_control_dispatch_end_v1",
                ActorAction
            ),
            observe: resolve!(
                c"qemu_plugin_crucible_ram_control_actor_observe_v1",
                Observe
            ),
            quiesce: resolve!(
                c"qemu_plugin_crucible_ram_control_actor_quiesce_v1",
                ActorAction
            ),
            quiesce_join: resolve!(
                c"qemu_plugin_crucible_ram_control_actor_quiesce_join_v1",
                ActorAction
            ),
        })
    }
}
