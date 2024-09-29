use aya_ebpf::{
    helpers::bpf_probe_read_user_buf, maps::PerfEventArray, programs::TracePointContext,
    EbpfContext,
};

#[allow(dead_code)]
#[repr(C, packed)]
pub struct EpollCtlArgs {
    pub pid: u32,
    pub epfd: u64,
    pub op: u64,
    pub fd: u64,
    pub epoll_event: [u8; 12],
    pub return_value: i64,
}

impl EpollCtlArgs {
    #[inline(always)]
    pub fn from_ctx(ctx: &TracePointContext) -> Option<Self> {
        let epoll_event_src: u64 = unsafe { ctx.read_at(40) }.unwrap_or(0);
        let mut dst: [u8; 12] = [0; 12];
        let res = unsafe { bpf_probe_read_user_buf(epoll_event_src as *const u8, &mut dst) };
        if res.is_ok() {
            return Some(Self {
                pid: ctx.pid(),
                epfd: unsafe { ctx.read_at(16) }.unwrap_or_default(),
                op: unsafe { ctx.read_at(24) }.unwrap_or_default(),
                fd: unsafe { ctx.read_at(32) }.unwrap_or_default(),
                epoll_event: dst,
                return_value: 0,
            });
        }
        None
    }

    #[inline(always)]
    pub fn send(&self, ctx: &TracePointContext, events: &PerfEventArray<Self>) {
        events.output(ctx, self, 0);
    }
}
