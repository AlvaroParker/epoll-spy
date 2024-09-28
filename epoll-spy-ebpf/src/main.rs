#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::bpf_probe_read_user_buf,
    macros::{map, tracepoint},
    maps::{HashMap, PerfEventArray},
    programs::TracePointContext,
    EbpfContext,
};

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

#[allow(dead_code)]
#[repr(C, packed)]
pub struct EpollCtlArgs {
    epfd: u64,
    op: u64,
    fd: u64,
    epoll_event: [u8; 12],
}

#[map]
pub static EVENTS: PerfEventArray<EpollCtlArgs> = PerfEventArray::with_max_entries(1024, 0);

/*
union epoll_data {
      void     *ptr;
      int       fd;
      uint32_t  u32;
      uint64_t  u64;
  };
*/

impl EpollCtlArgs {
    fn from_ctx(ctx: &TracePointContext) -> Option<Self> {
        let epoll_event_src: u64 = unsafe { ctx.read_at(40) }.unwrap_or(0);
        let mut dst: [u8; 12] = [0; 12];
        let res = unsafe { bpf_probe_read_user_buf(epoll_event_src as *const u8, &mut dst) };
        if res.is_ok() {
            return Some(Self {
                epfd: unsafe { ctx.read_at(16) }.unwrap_or_default(),
                op: unsafe { ctx.read_at(24) }.unwrap_or_default(),
                fd: unsafe { ctx.read_at(32) }.unwrap_or_default(),
                epoll_event: dst,
            });
        }
        None
    }
}

#[map]
static PIDS: HashMap<u32, u32> = HashMap::with_max_entries(32, 0);

#[tracepoint]
pub fn epoll_spy(ctx: TracePointContext) -> u32 {
    let pid = ctx.pid();
    if let Some(pid) = unsafe { PIDS.get(&pid) } {
        if pid == &1 {
            if let Some(args) = EpollCtlArgs::from_ctx(&ctx) {
                EVENTS.output(&ctx, &args, 0);
            }
        }
    }
    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
