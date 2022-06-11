#![feature(prelude_import)]
#![no_std]
#![no_main]
#[prelude_import]
use core::prelude::rust_2021::*;
#[macro_use]
extern crate core;
#[macro_use]
extern crate compiler_builtins;
use common::*;
use redbpf_macros::program;
use redbpf_probes::kprobe::prelude::*;
#[no_mangle]
#[link_section = "license"]
pub static _license: [u8; 4usize] = [71u8, 80u8, 76u8, 0u8];
#[no_mangle]
#[link_section = "version"]
pub static _version: u32 = 0xFFFFFFFE;
#[panic_handler]
#[no_mangle]
pub extern "C" fn rust_begin_panic(info: &::core::panic::PanicInfo) -> ! {
    use ::redbpf_probes::helpers::bpf_trace_printk;
    let msg: [u8; 6usize] = [112u8, 97u8, 110u8, 105u8, 99u8, 0u8];
    bpf_trace_printk(&msg);
    unsafe { core::hint::unreachable_unchecked() }
}
#[no_mangle]
#[link_section = "maps/OPEN_PATHS"]
static mut OPEN_PATHS: PerfMap<OpenPath> = PerfMap::with_max_entries(1024);
mod _d5a90905ed2c4672bc9c5eafb4846e18 {
    #[allow(unused_imports)]
    use super::*;
    use core::mem::{self, MaybeUninit};
    #[no_mangle]
    static MAP_VALUE_ALIGN_OPEN_PATHS: MaybeUninit<
        <PerfMap<OpenPath> as ::redbpf_probes::maps::BpfMap>::Value,
    > = MaybeUninit::uninit();
    #[repr(C)]
    struct ____btf_map_OPEN_PATHS {
        key: <PerfMap<OpenPath> as ::redbpf_probes::maps::BpfMap>::Key,
        value: <PerfMap<OpenPath> as ::redbpf_probes::maps::BpfMap>::Value,
    }
    unsafe impl Sync for ____btf_map_OPEN_PATHS {}
    const N: usize = mem::size_of::<____btf_map_OPEN_PATHS>();
    #[no_mangle]
    #[link_section = "maps.ext"]
    static MAP_BTF_OPEN_PATHS: ____btf_map_OPEN_PATHS =
        unsafe { mem::transmute::<[u8; N], ____btf_map_OPEN_PATHS>([0u8; N]) };
}
#[no_mangle]
#[link_section = "kprobe/do_sys_open"]
fn outer_do_sys_open(ctx: *mut c_void) -> i32 {
    let regs = ::redbpf_probes::registers::Registers::from(ctx);
    let _ = unsafe { do_sys_open(regs) };
    return 0;
    fn do_sys_open(regs: Registers) {
        let mut path = OpenPath::default();
        unsafe {
            let filename = regs.parm2() as *const u8;
            if bpf_probe_read_user_str(
                path.filename.as_mut_ptr() as *mut _,
                path.filename.len() as u32,
                filename as *const _,
            ) <= 0
            {
                bpf_trace_printk(b"error on bpf_probe_read_user_str\0");
                return;
            }
            OPEN_PATHS.insert(regs.ctx, &path);
        }
    }
}
