#![no_std]
#![no_main]

mod epoll_ctl;

use core::i64;

use aya_ebpf::{
    macros::{map, tracepoint},
    maps::{HashMap, PerfEventArray},
    programs::TracePointContext,
    EbpfContext,
};
use aya_log_ebpf::info;
use epoll_ctl::EpollCtlArgs;

#[map]
pub static EVENTS: PerfEventArray<EpollCtlArgs> = PerfEventArray::new(0);

#[map]
static PIDS: HashMap<u32, u32> = HashMap::with_max_entries(4096, 0);

#[map]
static EPOLL_CTL: HashMap<u32, EpollCtlArgs> = HashMap::with_max_entries(1024 * 10, 0);

#[tracepoint]
pub fn epoll_spy(ctx: TracePointContext) -> i32 {
    let pid = ctx.pid();
    if let Some(val) = unsafe { PIDS.get(&pid) } {
        if val == &1 {
            if let Some(args) = EpollCtlArgs::from_ctx(&ctx) {
                info!(&ctx, "Received epoll_ctl syscall from: {}", pid);
                _ = EPOLL_CTL.insert(&pid, &args, 0);
            }
        }
    }
    0
}

#[tracepoint]
pub fn epoll_spy_exit(ctx: TracePointContext) -> i32 {
    let pid = ctx.pid();
    if let Some(args) = unsafe { EPOLL_CTL.get(&pid) } {
        let return_value: i64 = unsafe { ctx.read_at(16) }.unwrap_or(-1);
        let args = EpollCtlArgs {
            pid: args.pid,
            epfd: args.epfd,
            op: args.op,
            fd: args.fd,
            epoll_event: args.epoll_event,
            return_value,
        };
        args.send(&ctx, &EVENTS);
    }
    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
