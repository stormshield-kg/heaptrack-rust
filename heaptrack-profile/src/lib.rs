use std::alloc::{GlobalAlloc, Layout};
use std::cell::Cell;
use std::collections::VecDeque;
use std::ffi::{CStr, c_int, c_void};
use std::fs::File;
use std::io::{self, Read, Seek, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::{slice, thread};

use libc::size_t;

type Writer = Box<dyn Write + Send>;

pub struct Heaptrack<T> {
    allocator: T,
    inner: HeaptrackInner,
}

impl<T> Heaptrack<T> {
    pub const fn new(allocator: T) -> Self {
        Self {
            allocator,
            inner: HeaptrackInner::new(),
        }
    }

    #[inline]
    pub fn init(&'static self, writer: Writer, rss_dump_interval: Option<Duration>) {
        self.inner.init(writer, rss_dump_interval)
    }

    #[inline]
    pub fn stop(&self) {
        self.inner.stop();
    }

    #[inline]
    pub fn handle_malloc(&self, size: usize, ptr: usize) {
        self.inner.handle_malloc(size, ptr);
    }

    #[inline]
    pub fn handle_free(&self, ptr: usize) {
        self.inner.handle_free(ptr);
    }

    #[inline]
    pub fn handle_realloc(&self, ptr: usize, size: usize, new_ptr: usize) {
        self.inner.handle_realloc(ptr, size, new_ptr);
    }
}

unsafe impl<T: GlobalAlloc + Sync> GlobalAlloc for Heaptrack<T> {
    #[inline]
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { self.allocator.alloc(layout) };
        self.inner.handle_malloc(layout.size(), ptr as usize);
        ptr
    }

    #[inline]
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { self.allocator.alloc_zeroed(layout) };
        self.inner.handle_malloc(layout.size(), ptr as usize);
        ptr
    }

    #[inline]
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { self.allocator.dealloc(ptr, layout) }
        self.inner.handle_free(ptr as usize);
    }

    #[inline]
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new_ptr = unsafe { self.allocator.realloc(ptr, layout, new_size) };
        self.inner.handle_free(ptr as usize);
        self.inner.handle_malloc(layout.size(), new_ptr as usize);
        new_ptr
    }
}

struct HeaptrackInner {
    state: Mutex<Option<HeaptrackState>>,
    enabled: AtomicBool,
}

impl HeaptrackInner {
    thread_local!(
        static RECURSIVE: Cell<bool> = const { Cell::new(false) };
    );

    fn with_lock(&self, f: impl FnOnce(&mut Option<HeaptrackState>)) {
        if !Self::RECURSIVE.replace(true) {
            f(&mut self.state.lock().expect("panicked while locked"));
            Self::RECURSIVE.set(false);
        }
    }

    const fn new() -> Self {
        Self {
            state: Mutex::new(None),
            enabled: AtomicBool::new(false),
        }
    }

    fn init(&'static self, writer: Writer, rss_dump_interval: Option<Duration>) {
        self.with_lock(|state| {
            if state.is_none() {
                let state = state.insert(HeaptrackState::init(writer));
                let stop_timer = state.stop_timer.clone();

                let _ = state.write_version();
                let _ = state.write_executable_path();
                let _ = state.write_executable_cmdline();
                let _ = state.write_page_info();
                let _ = state.write_proc_maps();

                thread::spawn(move || {
                    let rss_dump_interval =
                        rss_dump_interval.unwrap_or_else(|| Duration::from_millis(10));

                    while !stop_timer.load(Ordering::Acquire) {
                        thread::sleep(rss_dump_interval);

                        self.with_lock(|state| {
                            if let Some(state) = state {
                                let _ = state.write_timestamp();
                                let _ = state.write_rss();
                            }
                        });
                    }
                });
            }

            self.enabled.store(true, Ordering::Release);
        });
    }

    fn stop(&self) {
        self.enabled.fetch_and(false, Ordering::AcqRel);
        let mut state = self.state.lock().expect("panicked while locked");
        if let Some(state) = &mut *state {
            let _ = state.write_timestamp();
            let _ = state.write_rss();
            let _ = state.writer.flush();
        }
        *state = None;
    }

    #[inline(never)] // used to remove inner backtrace frames
    fn handle_malloc(&self, size: usize, ptr: usize) {
        if self.enabled.load(Ordering::Acquire) {
            self.with_lock(|state| {
                if let Some(state) = state {
                    let HeaptrackState { tree, writer, .. } = state;
                    let index = tree.index(writer);
                    let _ = writeln!(writer, "+ {size:x} {index:x} {ptr:x}");
                }
            })
        }
    }

    #[inline]
    fn handle_free(&self, ptr: usize) {
        if ptr != 0 && self.enabled.load(Ordering::Acquire) {
            self.with_lock(|state| {
                if let Some(state) = state {
                    let _ = writeln!(state.writer, "- {ptr:x}");
                }
            })
        }
    }

    #[inline]
    fn handle_realloc(&self, ptr: usize, size: usize, new_ptr: usize) {
        self.handle_free(ptr);
        self.handle_malloc(size, new_ptr);
    }

    fn handle_malloc_address() -> usize {
        Self::handle_malloc as *const () as usize
    }
}

struct HeaptrackState {
    tree: BacktraceTree,
    writer: Writer,
    start: Instant,
    proc_statm: Option<File>,
    stop_timer: Arc<AtomicBool>,
}

impl HeaptrackState {
    fn init(writer: Writer) -> Self {
        Self {
            tree: BacktraceTree::default(),
            writer,
            start: Instant::now(),
            proc_statm: File::open("/proc/self/statm").ok(),
            stop_timer: Arc::new(AtomicBool::new(false)),
        }
    }

    fn write_version(&mut self) -> io::Result<()> {
        // HeapTrack v1.6.80, file format v3
        self.writer.write_all(b"v 10650 3\n")
    }

    fn write_executable_path(&mut self) -> io::Result<()> {
        let mut buf = [0u8; 1024];
        let buf_ptr = buf.as_mut_ptr().cast();
        let n = unsafe { libc::readlink(c"/proc/self/exe".as_ptr(), buf_ptr, 1024) as usize };
        if n == 0 {
            return Ok(());
        }
        let Some(buf) = buf.get(..n) else {
            return Ok(());
        };
        write!(self.writer, "x {n:x} ")?;
        self.writer.write_all(buf)?;
        self.writer.write_all(b"\n")?;
        Ok(())
    }

    fn write_executable_cmdline(&mut self) -> io::Result<()> {
        let mut file = File::open("/proc/self/cmdline")?;
        let mut buf = [0u8; 4096];
        let n = file.read(&mut buf)?;
        if n == 0 {
            return Ok(());
        }
        let Some(buf) = buf.get_mut(..n - 1) else {
            return Ok(());
        };
        for x in buf.iter_mut() {
            if *x == 0 {
                *x = b' ';
            }
        }
        self.writer.write_all(b"X ")?;
        self.writer.write_all(buf)?;
        self.writer.write_all(b"\n")?;
        Ok(())
    }

    fn write_page_info(&mut self) -> io::Result<()> {
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        let physical_pages = unsafe { libc::sysconf(libc::_SC_PHYS_PAGES) };
        writeln!(self.writer, "I {page_size:x} {physical_pages:x}")
    }

    fn write_proc_maps(&mut self) -> io::Result<()> {
        unsafe extern "C" fn dl_iterate_phdr_callback(
            info: *mut libc::dl_phdr_info,
            _size: size_t,
            data: *mut c_void,
        ) -> c_int {
            unsafe {
                let info = &*info;
                let writer = &mut *data.cast::<Writer>();

                let mut filename = c"x";
                if !info.dlpi_name.is_null() && *info.dlpi_name != 0 {
                    filename = CStr::from_ptr(info.dlpi_name);
                }
                let filename = filename.to_bytes();

                let phdrs = slice::from_raw_parts(info.dlpi_phdr, info.dlpi_phnum as usize);

                let mut write = || {
                    write!(writer, "m {:x} ", filename.len())?;
                    writer.write_all(filename)?;
                    write!(writer, " {:x}", info.dlpi_addr)?;

                    for phdr in phdrs {
                        if phdr.p_type == libc::PT_LOAD {
                            write!(writer, " {:x} {:x}", phdr.p_vaddr, phdr.p_memsz)?;
                        }
                    }

                    writer.write_all(b"\n")
                };

                write().is_err() as _
            }
        }

        self.writer.write_all(b"m 1 -\n")?;

        unsafe {
            libc::dl_iterate_phdr(
                Some(dl_iterate_phdr_callback),
                (&mut self.writer as *mut Writer).cast(),
            )
        };

        Ok(())
    }

    fn write_timestamp(&mut self) -> io::Result<()> {
        writeln!(self.writer, "c {:x}", self.start.elapsed().as_millis())
    }

    fn write_rss(&mut self) -> io::Result<()> {
        if let Some(proc_statm) = &mut self.proc_statm {
            let mut buf = [0u8; 512];
            let n = proc_statm.read(&mut buf)?;
            if n == 0 {
                return Ok(());
            }
            proc_statm.seek(io::SeekFrom::Start(0))?;

            if let Some(buf) = buf.get(..n)
                && let Some(rss) = buf.split(|&x| x == b' ').nth(1)
                && let Ok(rss) = str::from_utf8(rss)
                && let Ok(rss) = rss.parse::<usize>()
            {
                writeln!(self.writer, "R {rss:x}")?;
            }
        }

        Ok(())
    }
}

struct BacktraceFrameTree {
    ip: usize,
    index: u32,
    children: Vec<BacktraceFrameTree>,
}

impl BacktraceFrameTree {
    fn new(ip: usize, index: u32) -> Self {
        Self {
            ip,
            index,
            children: Vec::new(),
        }
    }
}

struct BacktraceTree {
    frames_buffer: VecDeque<usize>,
    next_index: u32,
    root: BacktraceFrameTree,
}

impl Default for BacktraceTree {
    fn default() -> BacktraceTree {
        BacktraceTree {
            frames_buffer: VecDeque::new(),
            next_index: 1,
            root: BacktraceFrameTree::new(0, 0),
        }
    }
}

impl BacktraceTree {
    fn capture_frames(&mut self) {
        self.frames_buffer.clear();

        backtrace::trace(|frame| {
            let ip = frame.ip() as usize;
            if ip != 0 {
                self.frames_buffer.push_front(ip);
                if frame.symbol_address() as usize == HeaptrackInner::handle_malloc_address() {
                    self.frames_buffer.clear();
                }
            }
            true
        });
    }

    fn index(&mut self, writer: &mut Writer) -> u32 {
        self.capture_frames();

        let mut parent = &mut self.root;

        for &ip in &self.frames_buffer {
            let idx = match parent.children.binary_search_by(|tree| tree.ip.cmp(&ip)) {
                Ok(idx) => idx,
                Err(idx) => {
                    let frame = BacktraceFrameTree::new(ip, self.next_index);
                    parent.children.insert(idx, frame);
                    self.next_index += 1;
                    let _ = writeln!(writer, "t {:x} {:x}", ip - 1, parent.index);
                    idx
                }
            };
            parent = &mut parent.children[idx];
        }

        parent.index
    }
}
