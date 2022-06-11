use futures::stream::StreamExt;
use std::{ffi::CStr, ptr};

use common::OpenPath;
use redbpf::load::Loader;
fn probe_code() -> &'static [u8] {
    include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/target/bpf/programs/myapp-ebpf/myapp-ebpf.elf"
    ))
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let mut loaded = Loader::load(probe_code()).expect("error on Loader::load");

    let probe = loaded
        .kprobe_mut("do_sys_open")
        .expect("error on Loaded::kprobe_mut");
    probe
        .attach_kprobe("do_sys_open", 0)
        .expect("error on KProbe::attach_kprobe");
    probe
        .attach_kprobe("do_sys_openat2", 0)
        .expect("error on KProbe::attach_kprobe");

    while let Some((map_name, events)) = loaded.events.next().await {
        if map_name == "OPEN_PATHS" {
            for event in events {
                let open_path = unsafe { ptr::read(event.as_ptr() as *const OpenPath) };
                unsafe {
                    let cfilename = CStr::from_ptr(open_path.filename.as_ptr() as *const _);
                    println!("{}", cfilename.to_string_lossy());
                };
            }
        }
    }
}
