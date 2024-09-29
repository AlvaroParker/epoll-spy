use std::collections::HashSet;

use aya::maps::{AsyncPerfEventArray, HashMap};
use aya::programs::TracePoint;
use aya::util::online_cpus;
use aya::{include_bytes_aligned, Ebpf};
use bytes::BytesMut;
use clap::Parser;
use epoll::EpollCtl;
use follow_threads::get_threads;
use log::{debug, info};
use tokio::signal;

mod epoll;
mod follow_threads;

#[derive(Parser, Debug)]
pub struct Arguments {
    /// List of PIDs you want to track
    #[arg(short, long, value_delimiter = ',', required = true)]
    pid: Vec<u32>,

    /// Follow threads of the provided PIDs
    #[arg(long)]
    follow_threads: bool,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();
    let args = Arguments::parse();
    let mut pids: HashSet<u32> = args.pid.into_iter().collect();
    if args.follow_threads {
        get_threads(&mut pids);
        println!("Final pids: {}", pids.len())
    }

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/epoll-spy"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/epoll-spy"
    ))?;

    let program1: &mut TracePoint = bpf.program_mut("epoll_spy").unwrap().try_into()?;
    program1.load()?;
    program1.attach("syscalls", "sys_enter_epoll_ctl")?;

    let program2: &mut TracePoint = bpf.program_mut("epoll_spy_exit").unwrap().try_into()?;
    program2.load()?;
    program2.attach("syscalls", "sys_exit_epoll_ctl")?;

    match bpf.map_mut("PIDS") {
        Some(hm) => {
            let mut pid_map: HashMap<_, u32, u32> = HashMap::try_from(hm)?;
            for pid in pids.iter() {
                _ = pid_map.insert(pid, 1, 0);
            }
        }
        None => {}
    }
    let perf_array = bpf.take_map("EVENTS").unwrap();
    let mut perf_array = AsyncPerfEventArray::try_from(perf_array)?;

    for cpu in online_cpus()? {
        let mut buf = perf_array.open(cpu, None)?;
        let mut bufs = (0..10)
            .map(|_| BytesMut::with_capacity(1024))
            .collect::<Vec<_>>();
        tokio::spawn(async move {
            loop {
                let events = buf.read_events(&mut bufs).await.unwrap();
                for i in 0..events.read {
                    let buf = bufs[i].to_owned();
                    if let Some(epoll_ctl) = EpollCtl::new(buf) {
                        println!("{}", epoll_ctl);
                    }
                }
            }
        });
    }

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
