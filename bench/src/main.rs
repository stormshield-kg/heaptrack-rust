use std::time::Instant;

use heaptrack_profile::Heaptrack;
use tikv_jemallocator::Jemalloc;

#[global_allocator]
static HEAPTRACK: Heaptrack<Jemalloc> = Heaptrack::new(Jemalloc);

#[inline(never)]
fn do_work() {
    let mut c = 0;
    for _ in 0..100 {
        let v = (0..100 + c / 100).collect::<Vec<_>>();
        c += v.len();
    }
}

fn main() {
    let start = Instant::now();

    for _ in 0..1000000 {
        do_work();
    }

    let end = Instant::now();

    println!("{:?}", (end - start));
}
