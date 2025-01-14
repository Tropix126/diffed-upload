use object::{Object, ObjectSegment, ObjectSymbol};

use std::io::Write;

use flate2::{Compression, GzBuilder};
use tokio::fs::{self, File};

const A: &[u8; include_bytes!("./basic.bin").len()] = include_bytes!("./basic.bin");
const B: &[u8; include_bytes!(
    "/home/tropical/Documents/GitHub/vexide/target/armv7a-vex-v5/release/examples/basic"
)
 .len()] = include_bytes!(
    "/home/tropical/Documents/GitHub/vexide/target/armv7a-vex-v5/release/examples/basic"
);

#[tokio::main]
async fn main() {
    // this print somehow makes elf parsing magically work
    // what the FUCK??
    println!("{:?}", &B[0..2]);

    // Parse the ELF file.
    let elf_data = object::File::parse(B.as_slice()).unwrap();
    let __heap_start_address = elf_data.symbol_by_name("__heap_start").unwrap().address();
    println!("__heap_start: {:#x?}", __heap_start_address);

    let objcopied_b = {
        // Get the loadable segments (program data) and sort them by virtual address.
        let mut program_segments: Vec<_> = elf_data.segments().collect();
        program_segments.sort_by_key(|seg| seg.address());

        // used to fill gaps between segments with zeros
        let mut last_addr = program_segments.first().unwrap().address();

        // final objcopied binary
        let mut bytes = Vec::new();

        // Concatenate all the segments into a single binary.
        for segment in program_segments {
            // Fill gaps between segments with zeros.
            let gap = segment.address() - last_addr;
            if gap > 0 {
                bytes.extend(vec![0; gap as usize]);
            }

            // Push the segment data to the binary.
            let data = segment.data().unwrap();
            bytes.extend_from_slice(data);

            // data.len() can be different from segment.size() so we use the actual data length
            last_addr = segment.address() + data.len() as u64;
        }

        // Write the binary to a file.
        bytes
    };

    let mut buf = Vec::new();

    bidiff::simple_diff(A, &objcopied_b, &mut buf).unwrap();

    // Insert important metadata for the patcher to use when constructing a new binary
    buf.reserve(16);
    buf.splice(8..8, ((buf.len() + 16) as u32).to_le_bytes());
    buf.splice(12..12, (A.len() as u32).to_le_bytes());
    buf.splice(16..16, (objcopied_b.len() as u32).to_le_bytes());
    buf.splice(20..20, (__heap_start_address as u32).to_le_bytes());

    println!(
        "patch len: {}, old len: {}, new len: {}",
        buf.len(),
        A.len(),
        objcopied_b.len()
    );

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
