use std::cell::RefCell;
use std::collections::hash_map::Entry;
use std::collections::{HashMap, VecDeque};
use std::ffi::{OsStr, OsString};
use std::fmt::Write as _;
use std::fs;
use std::hash::Hash;
use std::io::{self, BufRead, Write};
use std::iter;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Component, Path, PathBuf};
use std::rc::Rc;

use addr2line::Loader;
use addr2line::fallible_iterator::FallibleIterator;
use object::Object;
use rustc_hash::{FxBuildHasher, FxHashMap};

struct SplitPointer {
    high: u64,
    low: u16,
}

impl SplitPointer {
    const PAGE_SIZE_BITS: u64 = 14;
    const PAGE_SIZE: u64 = 1 << Self::PAGE_SIZE_BITS;

    fn new(ptr: u64) -> Self {
        Self {
            high: ptr >> Self::PAGE_SIZE_BITS,
            low: (ptr % Self::PAGE_SIZE) as u16,
        }
    }
}

#[derive(Default)]
struct Indices {
    low_ptrs: Vec<u16>,
    allocation_indices: Vec<u32>,
}

struct PointerMap {
    map: FxHashMap<u64, Indices>,
}

impl PointerMap {
    fn new() -> Self {
        Self {
            map: HashMap::with_capacity_and_hasher(1024, FxBuildHasher),
        }
    }

    fn insert(&mut self, ptr: u64, allocation_index: u32) {
        let ptr = SplitPointer::new(ptr);

        let indices = self.map.entry(ptr.high).or_default();

        match indices.low_ptrs.binary_search(&ptr.low) {
            Ok(idx) => indices.allocation_indices[idx] = allocation_index,
            Err(idx) => {
                indices.low_ptrs.insert(idx, ptr.low);
                indices.allocation_indices.insert(idx, allocation_index);
            }
        }
    }

    fn remove(&mut self, ptr: u64) -> Option<u32> {
        let ptr = SplitPointer::new(ptr);

        let Entry::Occupied(mut entry) = self.map.entry(ptr.high) else {
            return None;
        };
        let indices = entry.get_mut();

        let idx = indices.low_ptrs.binary_search(&ptr.low).ok()?;

        let allocation_index = indices.allocation_indices.remove(idx);
        indices.low_ptrs.remove(idx);

        if indices.allocation_indices.is_empty() {
            entry.remove();
        }

        Some(allocation_index)
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Hash)]
struct Allocation {
    size: u64,
    trace_index: u32,
}

struct AllocationMap {
    map: FxHashMap<Allocation, u32>,
}

impl AllocationMap {
    fn new() -> Self {
        Self {
            map: HashMap::with_capacity_and_hasher(625000, FxBuildHasher),
        }
    }

    fn insert(&mut self, allocation: Allocation, output: &mut dyn Write) -> io::Result<u32> {
        let len = self.map.len();

        match self.map.entry(allocation) {
            Entry::Occupied(entry) => Ok(*entry.get()),
            Entry::Vacant(entry) => {
                let index = *entry.insert(len as u32);

                let (size, trace_index) = (allocation.size, allocation.trace_index);
                writeln!(output, "a {size:x} {trace_index:x}")?;

                Ok(index)
            }
        }
    }
}

struct IpMap {
    map: FxHashMap<usize, usize>,
}

impl IpMap {
    fn new() -> Self {
        Self {
            map: HashMap::with_capacity_and_hasher(32768, FxBuildHasher),
        }
    }

    fn insert(&mut self, ip: usize) -> (usize, bool) {
        if ip == 0 {
            return (0, false);
        }

        let len = self.map.len();

        match self.map.entry(ip) {
            Entry::Occupied(entry) => (*entry.get(), false),
            Entry::Vacant(entry) => (*entry.insert(len + 1), true),
        }
    }
}

struct InternedMap;

impl InternedMap {
    thread_local! {
        static MAP: RefCell<FxHashMap<&'static str, usize>> =
            RefCell::new(HashMap::with_capacity_and_hasher(4096, FxBuildHasher));
    }

    fn insert(s: &str, output: &mut dyn Write) -> io::Result<usize> {
        if s.is_empty() {
            return Ok(0);
        }

        Self::MAP.with_borrow_mut(|map| {
            if let Some(&index) = map.get(s) {
                return Ok(index);
            }

            let s = Box::<str>::leak(s.into());

            let index = map.len() + 1;
            map.insert(s, index);

            writeln!(output, "s {:x} {s}", s.len())?;

            Ok(index)
        })
    }
}

#[derive(Default)]
struct ResolvedFrame {
    function_index: usize,
    file_index: usize,
    line: u32,
}

#[derive(Default)]
struct ResolvedIp {
    frame: ResolvedFrame,
    inlined_frames: Vec<ResolvedFrame>,
}

impl ResolvedIp {
    fn new(loader: &Loader, relative_ip: u64, output: &mut dyn Write) -> io::Result<Self> {
        let mut frames = loader
            .find_frames(relative_ip)
            .map_err(|err| io::Error::other(err.to_string()))?
            .peekable();

        let mut first_frame = None;
        let mut inlined_frames = Vec::new();

        if matches!(frames.peek(), Ok(None)) {
            let function = loader.find_symbol(relative_ip).unwrap_or_default();
            let function = addr2line::demangle_auto(function.into(), None);

            first_frame = Some(ResolvedFrame {
                function_index: InternedMap::insert(&function, output)?,
                ..Default::default()
            });
        } else {
            while let Some(frame) = frames
                .next()
                .map_err(|err| io::Error::other(err.to_string()))?
            {
                let symbol = if matches!(frames.peek(), Ok(None)) {
                    loader.find_symbol(relative_ip)
                } else {
                    None
                };

                let function = if symbol.is_some() {
                    symbol.map(|x| x.into())
                } else {
                    frame.function.as_ref().and_then(|f| f.raw_name().ok())
                };

                let function = function.as_deref().unwrap_or_default();
                let function = addr2line::demangle_auto(function.into(), None);

                let mut resolved_frame = ResolvedFrame {
                    function_index: InternedMap::insert(&function, output)?,
                    ..Default::default()
                };

                if let Some(location) = frame.location {
                    if let Some(file) = location.file {
                        resolved_frame.file_index = InternedMap::insert(file, output)?;
                    }
                    if let Some(line) = location.line {
                        resolved_frame.line = line;
                    }
                }

                if first_frame.is_none() {
                    first_frame = Some(resolved_frame)
                } else {
                    inlined_frames.push(resolved_frame);
                }
            }
        }

        Ok(Self {
            frame: first_frame.unwrap_or_default(),
            inlined_frames,
        })
    }

    fn dump(&self, ip: usize, module_index: usize, output: &mut dyn Write) -> io::Result<()> {
        write!(output, "i {ip:x} {module_index:x}")?;

        if (self.frame.function_index != 0) || (self.frame.file_index != 0) {
            write!(output, " {:x}", self.frame.function_index)?;

            if self.frame.file_index != 0 {
                write!(output, " {:x} {:x}", self.frame.file_index, self.frame.line)?;

                for frame in &self.inlined_frames {
                    let ResolvedFrame {
                        function_index,
                        file_index,
                        line,
                    } = frame;

                    write!(output, " {function_index:x} {file_index:x} {line:x}")?;
                }
            }
        }

        output.write_all(b"\n")
    }
}

struct FileResolver {
    sysroot: PathBuf,
    debug_paths: Vec<PathBuf>,
    extra_paths: Vec<PathBuf>,
}

impl FileResolver {
    fn new(sysroot: Option<PathBuf>, debug_paths: Vec<PathBuf>, extra_paths: Vec<PathBuf>) -> Self {
        Self {
            sysroot: sysroot.unwrap_or_else(|| PathBuf::from("/".to_owned())),
            debug_paths,
            extra_paths,
        }
    }

    fn resolve(&self, module_path: &str) -> PathBuf {
        let exists = |path: &Path| fs::exists(path).is_ok_and(|x| x);

        let find_module = || {
            if let Some(filename) = Path::new(module_path).file_name() {
                for extra_path in &self.extra_paths {
                    let path = Path::new(extra_path).join(filename);
                    if exists(&path) {
                        return path;
                    }
                }
            }

            for sysroot_path in iter::chain(&self.extra_paths, [&self.sysroot]) {
                let module_path = module_path.strip_prefix("/").unwrap_or(module_path);
                let path = Path::new(sysroot_path).join(module_path);
                if exists(&path) {
                    return path;
                }
            }

            Path::new(module_path).into()
        };

        let resolved_path = find_module();

        let Ok(file) = fs::read(&resolved_path) else {
            return resolved_path;
        };

        let Ok(object) = object::File::parse(&file[..]) else {
            return resolved_path;
        };

        if object.section_by_name(".debug_info").is_some() {
            return resolved_path;
        }

        let sysroot_debug_search_path = self.sysroot.join(Path::new("usr/lib/debug"));

        let search_paths = iter::chain(&self.debug_paths, &self.extra_paths)
            .chain([&sysroot_debug_search_path])
            .collect::<Vec<_>>();

        if let Ok(Some([id_head, id_tail @ ..])) = object.build_id() {
            let mut relative_debug_file_path = format!(".build-id/{id_head:02x}/");
            for x in id_tail {
                let _ = write!(relative_debug_file_path, "{:02x}", x);
            }
            let _ = write!(&mut relative_debug_file_path, ".debug");

            for search_path in &search_paths {
                let debug_file_path = search_path.join(&relative_debug_file_path);
                if exists(&debug_file_path) {
                    return debug_file_path;
                }
            }
        }

        let (Some(parent), Some(filename)) = (resolved_path.parent(), resolved_path.file_name())
        else {
            return resolved_path;
        };

        let debug_filename = match object.gnu_debuglink() {
            Ok(Some((debug_filename, _))) => Path::new(OsStr::from_bytes(debug_filename)).into(),
            _ => PathBuf::from(OsString::from_vec(
                [filename.as_bytes(), b".debug"].concat(),
            )),
        };

        let debug_file_path = parent.join(&debug_filename);
        if exists(&debug_file_path) {
            return debug_file_path;
        }

        let separate_debug_file_path =
            PathBuf::from_iter([parent, Path::new(".debug"), &debug_filename]);

        if exists(&separate_debug_file_path) {
            return separate_debug_file_path;
        }

        let mut debug_file_path_components = debug_file_path.components().collect::<VecDeque<_>>();
        if matches!(debug_file_path_components.front(), Some(Component::RootDir)) {
            debug_file_path_components.pop_front();
        }

        for search_path in &search_paths {
            let search_path_components = search_path.components().collect::<Vec<_>>();
            let mut debug_file_path_components = debug_file_path_components.clone();

            while !debug_file_path_components.is_empty() {
                let reduced_debug_file_path = PathBuf::from_iter(iter::chain(
                    &search_path_components,
                    &debug_file_path_components,
                ));

                if exists(&reduced_debug_file_path) {
                    return reduced_debug_file_path;
                }

                debug_file_path_components.pop_front();
            }
        }

        resolved_path
    }
}

fn read_optional_hex<'a>(iter: &mut impl Iterator<Item = &'a str>) -> io::Result<Option<u64>> {
    let Some(s) = iter.next() else {
        return Ok(None);
    };

    u64::from_str_radix(s, 16)
        .map_err(|_| io::Error::other(format!("invalid hex: {s}")))
        .map(Some)
}

fn read_hex<'a>(iter: &mut impl Iterator<Item = &'a str>, line_number: usize) -> io::Result<u64> {
    read_optional_hex(iter)?.ok_or_else(|| {
        io::Error::other(format!("failed to parse line {line_number}: invalid line"))
    })
}

fn read_sized_str<'a>(iter: &mut impl Iterator<Item = &'a str>) -> io::Result<&'a str> {
    let len = read_optional_hex(iter)?.ok_or_else(|| io::Error::other("invalid line"))?;

    let data = (iter.next()).ok_or_else(|| io::Error::other("invalid line"))?;

    if data.len() as u64 != len {
        return Err(io::Error::other("invalid data length"));
    }

    Ok(data)
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct Module {
    address_start: usize,
    fragment_start: usize,
    fragment_end: usize,
    module_index: usize,
}

pub fn interpret(
    input: &mut dyn BufRead,
    output: &mut dyn Write,
    sysroot: Option<PathBuf>,
    debug_paths: Vec<PathBuf>,
    extra_paths: Vec<PathBuf>,
) -> io::Result<()> {
    let file_resolver = FileResolver::new(sysroot, debug_paths, extra_paths);

    let mut executable_path = None;
    let mut ips = IpMap::new();
    let mut allocations = AllocationMap::new();
    let mut ptrs = PointerMap::new();
    let mut modules = Vec::with_capacity(256);
    let mut loaders = Vec::with_capacity(256);

    for (line_number, line) in input.lines().enumerate() {
        let line_number = line_number + 1;
        let line = line?;

        let mut iter = line.split(' ');

        match iter.next() {
            Some("v") => {
                if iter.nth(1) != Some("3") {
                    return Err(io::Error::other(format!(
                        "failed to parse line {line_number}: invalid file version"
                    )));
                }

                output.write_all(line.as_bytes())?;
                output.write_all(b"\n")?;
            }
            Some("x") => {
                if executable_path.is_some() {
                    return Err(io::Error::other(format!(
                        "failed to parse line {line_number}: duplicate executable path"
                    )));
                }

                executable_path = Some(
                    read_sized_str(&mut iter)
                        .map_err(|err| {
                            io::Error::other(format!(
                                "failed to parse line {line_number}: invalid executable path: {err}"
                            ))
                        })?
                        .to_owned(),
                );
            }
            Some("m") => {
                let mut module_path = read_sized_str(&mut iter).map_err(|err| {
                    io::Error::other(format!(
                        "failed to parse line {line_number}: invalid module path: {err}"
                    ))
                })?;

                if module_path == "-" {
                    modules.clear();
                    loaders.clear();
                    continue;
                }

                if module_path == "x" {
                    module_path = executable_path.as_deref().unwrap_or_default();
                }
                let module_index = InternedMap::insert(module_path, output)?;

                let loader = Rc::new(Loader::new(file_resolver.resolve(module_path)).ok());

                let address_start = read_hex(&mut iter, line_number)?;

                while let (Some(v_addr), Some(mem_size)) =
                    (read_optional_hex(&mut iter)?, read_optional_hex(&mut iter)?)
                {
                    let module = Module {
                        address_start: address_start as usize,
                        fragment_start: (address_start + v_addr) as usize,
                        fragment_end: (address_start + v_addr + mem_size) as usize,
                        module_index,
                    };

                    let idx = modules.binary_search(&module).unwrap_or_else(|idx| idx);
                    modules.insert(idx, module);
                    loaders.insert(idx, loader.clone());
                }
            }
            Some("t") => {
                let ip = read_hex(&mut iter, line_number)? as usize;
                let parent_index = read_hex(&mut iter, line_number)?;

                let (ip_index, inserted) = ips.insert(ip);
                if !inserted {
                    writeln!(output, "t {ip_index:x} {parent_index:x}")?;
                    continue;
                }

                let mut module_index = 0;
                let mut resolved_ip = ResolvedIp::default();

                let idx = modules.partition_point(|m| m.fragment_end <= ip);

                if let Some(module) = modules.get(idx)
                    && module.fragment_start <= ip
                    && let Some(loader) = &*loaders[idx]
                {
                    let relative_ip = (ip - module.address_start) as u64;

                    module_index = module.module_index;
                    resolved_ip = ResolvedIp::new(loader, relative_ip, output)?
                }

                resolved_ip.dump(ip, module_index, output)?;

                writeln!(output, "t {ip_index:x} {parent_index:x}")?;
            }
            Some("+") => {
                let size = read_hex(&mut iter, line_number)?;
                let trace_index = read_hex(&mut iter, line_number)? as u32;
                let ptr = read_hex(&mut iter, line_number)?;

                let allocation = Allocation { size, trace_index };
                let allocation_index = allocations.insert(allocation, output)?;

                ptrs.insert(ptr, allocation_index);
                writeln!(output, "+ {allocation_index:x}")?;
            }
            Some("-") => {
                let ptr = read_hex(&mut iter, line_number)?;
                if let Some(allocation_index) = ptrs.remove(ptr) {
                    writeln!(output, "- {allocation_index:x}")?;
                }
            }
            _ => {
                output.write_all(line.as_bytes())?;
                output.write_all(b"\n")?;
            }
        }
    }

    output.flush()
}
