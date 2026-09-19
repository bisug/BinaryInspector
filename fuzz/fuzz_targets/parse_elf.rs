#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = binary_inspector::elf::parse(data, data.len() as u64);
});

