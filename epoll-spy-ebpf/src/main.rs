#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{map, tracepoint},
    maps::HashMap,
    programs::TracePointContext,
    EbpfContext,
};
use aya_log_ebpf::info;
/*
name: sys_enter_epoll_ctl
ID: 1007
format:
    field:unsigned short common_type;	offset:0;	size:2;	signed:0;
    field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
    field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
    field:int common_pid;	offset:4;	size:4;	signed:1;

    field:int __syscall_nr;	offset:8;	size:4;	signed:1;
    field:int epfd;	offset:16;	size:8;	signed:0;
    field:int op;	offset:24;	size:8;	signed:0;
    field:int fd;	offset:32;	size:8;	signed:0;
    field:struct epoll_event * event;	offset:40;	size:8;	signed:0;
*/

pub struct EpollCtlArgs {
    epfd: u64,
    op: u64,
    fd: u64,
    epoll_event: u64,
}
impl EpollCtlArgs {
    fn from_ctx(ctx: &TracePointContext) -> Self {
        Self {
            epfd: unsafe { ctx.read_at(16) }.unwrap_or_default(),
            op: unsafe { ctx.read_at(24) }.unwrap_or_default(),
            fd: unsafe { ctx.read_at(32) }.unwrap_or_default(),
            epoll_event: unsafe { ctx.read_at(40) }.unwrap_or_default(),
        }
    }

    fn log(&self, ctx: &TracePointContext) {
        info!(
            ctx,
            "EpollCtlArgs {{ epfd: {}, op: {}, fd: {}, epoll_event: {} }}",
            self.epfd,
            self.op,
            self.fd,
            self.epoll_event
        )
    }
}

#[map]
static PIDS: HashMap<u32, u32> = HashMap::with_max_entries(32, 0);

#[tracepoint]
pub fn epoll_spy(ctx: TracePointContext) -> u32 {
    let pid = ctx.pid();
    if let Some(pid) = unsafe { PIDS.get(&pid) } {
        if pid == &1 {
            let args = EpollCtlArgs::from_ctx(&ctx);
            args.log(&ctx);
        }
    }
    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
