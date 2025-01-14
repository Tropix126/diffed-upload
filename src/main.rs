pub mod varint_slop;

use varint_slop::VarIntReader;

use std::io::{Cursor, Read, Seek, SeekFrom, Write};

use flate2::{Compression, GzBuilder};
use tokio::fs::{self, File};

const A: &[u8; include_bytes!("./basic.bin").len()] = include_bytes!("./basic.bin");
const B: &[u8; include_bytes!(
    "/home/tropical/Documents/GitHub/vexide/target/armv7a-vex-v5/debug/examples/basic.bin"
)
 .len()] = include_bytes!(
    "/home/tropical/Documents/GitHub/vexide/target/armv7a-vex-v5/debug/examples/basic.bin"
);

#[tokio::main]
async fn main() {
    let mut buf = Vec::new();

    bidiff::simple_diff(A, B, &mut buf).unwrap();

    buf.reserve(12);
    buf.splice(8..8, ((buf.len() + 12) as u32).to_le_bytes());
    buf.splice(12..12, (A.len() as u32).to_le_bytes());
    buf.splice(16..16, (B.len() as u32).to_le_bytes());

    println!(
        "patch len: {}, old len: {}, new len: {}",
        buf.len(),
        A.len(),
        B.len()
    );

    test_patch(&buf, A);

    fs::write("./src/bin.patch", buf).await.unwrap();

    let mut gz = GzBuilder::new().write(
        File::create("./src/bin.patch.gz")
            .await
            .unwrap()
            .try_into_std()
            .unwrap(),
        Compression::default(),
    );

    gz.write_all(&fs::read("./src/bin.patch").await.unwrap())
        .unwrap();
    gz.finish().unwrap();
}

#[derive(Debug)]
enum PatcherState {
    Initial,
    Add(usize),
    Copy(usize),
}

fn test_patch(patch: &[u8], old: &[u8]) {
    let mut membuf = vec![0; 0x8000000];
    let mem = membuf.as_mut_ptr();

    unsafe {
        core::ptr::copy_nonoverlapping(old.as_ptr(), mem.offset(0x0380_0000), old.len());
        core::ptr::copy_nonoverlapping(patch.as_ptr(), mem.offset(0x0780_0000), patch.len());
    }


    'patch: {
        const PATCH_MAGIC: u32 = 0xB1DF;
        const PATCH_VERSION: u32 = 0x1000;
        let USER_MEMORY_START: u32 = unsafe { mem.offset(0x0380_0000) } as u32;
        let PATCH_MEMORY_START: u32 = unsafe { mem.offset(0x0780_0000) } as u32;

        let link_addr = unsafe { vex_sdk::vexSystemLinkAddrGet() };

        // This means we might potentially have a patch that needs to be applied.
        if link_addr == USER_MEMORY_START {
            // Pointer to the linked file in memory.
            let patch_ptr = PATCH_MEMORY_START as *mut u32;

            unsafe {
                // We first need to validate that the linked file is indeed a patch. The first 32 bits
                // (starting at link_addr+0) should always be 0xB1DF, and the 32 bits after should contain
                // a version constant that matches ours. If either of these checks fail, then we boot normally.
                if patch_ptr.read() != PATCH_MAGIC || patch_ptr.offset(1).read() != PATCH_VERSION {
                    // TODO: reclaim as heap space.
                    break 'patch;
                }

                // Overwrite patch magic so we don't re-apply the patch next time.
                patch_ptr.write(0xB2DF);

                // Next few bytes contain metadata about how large our current binary is, as well as the length of
                // the patch itself. We need this for the next step.
                let patch_len = patch_ptr.offset(2).read();
                let old_binary_len = patch_ptr.offset(3).read();
                let new_binary_len = patch_ptr.offset(4).read();

                // We have to ensure that the heap does not overlap the memory space from the new binary.
                // vexide_core::allocator::claim(
                //     (USER_MEMORY_START + new_binary_len) as *mut u8,
                //     &raw mut __heap_end,
                // );

                // Slice representing our patch contents.
                let mut patch = core::slice::from_raw_parts(
                    patch_ptr.offset(5).cast(),
                    patch_len as usize - (size_of::<u32>() * 5),
                );

                // Slice of the executable portion of the currently running program (this one!)
                let mut old = Cursor::new(core::slice::from_raw_parts_mut(
                    USER_MEMORY_START as *mut u8,
                    old_binary_len as usize,
                ));

                // `bidiff` does not patch in-place, meaning we need a copy of our currently running binary on the heap
                // that we will apply our patch to using our actively running binary as a reference point for the "old" bits.
                // After that, `apply_patch` will handle safely overwriting user code with our "new" version on the heap.
                let mut new_vec = vec![0; new_binary_len as usize];
                let mut new: &mut [u8] = new_vec.as_mut_slice();

                // Apply the patch onto `new`, using `old` as a reference.
                //
                // This is basically a port of <https://github.com/divvun/bidiff/blob/main/crates/bipatch/src/lib.rs>

                let mut buf = vec![0u8; 4096];

                let mut state = PatcherState::Initial;

                while !new.is_empty() {
                    let processed = match state {
                        PatcherState::Initial => {
                            state = PatcherState::Add(patch.read_varint().unwrap());
                            0
                        }
                        PatcherState::Add(add_len) => {
                            let n = add_len.min(new.len()).min(buf.len());

                            let out = &mut new[..n];
                            old.read_exact(out).unwrap();

                            let dif = &mut buf[..n];
                            patch.read_exact(dif).unwrap();

                            for i in 0..n {
                                out[i] = out[i].wrapping_add(dif[i]);
                            }

                            state = if add_len == n {
                                let copy_len: usize = patch.read_varint().unwrap();
                                PatcherState::Copy(copy_len)
                            } else {
                                PatcherState::Add(add_len - n)
                            };

                            n
                        }
                        PatcherState::Copy(copy_len) => {
                            let n = copy_len.min(new.len());

                            let out = &mut new[..n];
                            patch.read_exact(out).unwrap();

                            state = if copy_len == n {
                                let seek: i64 = patch.read_varint().unwrap();
                                old.seek(SeekFrom::Current(seek)).unwrap();

                                PatcherState::Initial
                            } else {
                                PatcherState::Copy(copy_len - n)
                            };

                            n
                        }
                    };

                    new = &mut new[processed..];
                }

                overwrite_with_patched(&new_vec, mem);
            }
        }
    }
}

mod vex_sdk {
    #[allow(non_snake_case)]
    pub unsafe extern "C" fn vexSystemLinkAddrGet() -> u32 {
        0x0380_0000
    }
}

// TODO: rewrite in assembly to prevent this function from possibly patching itself due to
// differences between debug/release codegen and rustc updates.
#[unsafe(link_section = ".overwriter")]
#[inline(never)]
unsafe fn overwrite_with_patched(new: &[u8], mem: *mut u8) {
    unsafe {
        core::ptr::copy_nonoverlapping(new.as_ptr(), mem.offset(0x0380_0000), new.len());
    }
    
    assert_eq!(
        unsafe { core::slice::from_raw_parts(mem.offset(0x0380_0000), new.len()) },
        *B
    );
}