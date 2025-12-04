use std::io::{stdin, stdout};
use std::path::PathBuf;

use clap::Parser;

/// heaptrack_interpret - interpret raw heaptrack data files
#[derive(Parser)]
struct Args {
    /// Path to a system root directory
    #[arg(long)]
    sysroot: Option<PathBuf>,
    /// Paths to folders containing extra debug symbols
    #[arg(long)]
    debug_paths: Vec<PathBuf>,
    /// Paths to folders containing additional executables or libraries with debug symbols
    #[arg(long)]
    extra_paths: Vec<PathBuf>,
}

fn main() -> Result<(), String> {
    let args = Args::parse();

    let mut input = stdin().lock();
    let mut output = stdout().lock();

    heaptrack_interpret::interpret(
        &mut input,
        &mut output,
        args.sysroot,
        args.debug_paths,
        args.extra_paths,
    )
    .map_err(|err| err.to_string())
}
