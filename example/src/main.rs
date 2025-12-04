use std::ffi::c_void;
use std::fs::File;
use std::io::{self, BufReader, BufWriter};

use heaptrack_profile::Heaptrack;
use tikv_jemallocator::Jemalloc;

#[global_allocator]
static HEAPTRACK: Heaptrack<Jemalloc> = Heaptrack::new(Jemalloc);

#[unsafe(no_mangle)]
fn malloc(size: usize) -> *mut c_void {
    let ptr = unsafe { tikv_jemalloc_sys::malloc(size) };
    HEAPTRACK.handle_malloc(size, ptr as usize);
    ptr
}

#[unsafe(no_mangle)]
fn calloc(number: usize, size: usize) -> *mut c_void {
    let ptr = unsafe { tikv_jemalloc_sys::calloc(number, size) };
    HEAPTRACK.handle_malloc(size, ptr as usize);
    ptr
}

#[unsafe(no_mangle)]
fn realloc(ptr: *mut c_void, size: usize) -> *mut c_void {
    let new_ptr = unsafe { tikv_jemalloc_sys::realloc(ptr, size) };
    HEAPTRACK.handle_realloc(ptr as usize, size, new_ptr as usize);
    new_ptr
}

#[unsafe(no_mangle)]
fn free(ptr: *mut c_void) {
    unsafe { tikv_jemalloc_sys::free(ptr) };
    HEAPTRACK.handle_free(ptr as usize);
}

#[inline(never)]
fn do_work() {
    let mut c = 0;
    for _ in 0..100 {
        let v = (0..1000000 + c / 1000000).collect::<Vec<_>>();
        c += v.len();
    }
}

fn main() -> io::Result<()> {
    std::fs::create_dir_all("out")?;

    let raw_path = "out/dump-raw.txt";
    let interpreted_path = "out/dump.txt";

    let writer = BufWriter::new(File::create(raw_path)?);

    HEAPTRACK.init(Box::new(writer), None);

    std::thread::scope(|s| {
        for _ in 0..10 {
            s.spawn(|| {
                do_work();
            });
        }
    });

    HEAPTRACK.stop();

    let mut input = BufReader::new(File::open(raw_path)?);
    let mut output = BufWriter::new(File::create(interpreted_path)?);

    heaptrack_interpret::interpret(&mut input, &mut output, None, Vec::new(), Vec::new())
}
