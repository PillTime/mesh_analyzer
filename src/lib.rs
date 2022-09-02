#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
mod binds;
pub use crate::binds::{
    Action, Event as RawEvent, CHECK_QOS, HAS_ADDR4, HAS_QOS, HDR_SIZE_3ADDR, HDR_SIZE_4ADDR,
};

#[path = "./bpf/.output/tracer.skel.rs"]
mod tracer;
pub use crate::tracer::*;

use std::{
    fmt,
    time::{Duration, SystemTime},
};

use lazy_static::lazy_static;
use libc::ETH_ALEN;
use psutil::host::boot_time;
use serde::{Deserialize, Serialize};

lazy_static! {
    static ref BOOT_TIME: SystemTime = boot_time().expect("get system boot time");
}

pub type MacAddr = [u8; ETH_ALEN as usize];

pub trait MacAddrT {
    fn hex(&self) -> String;
}

impl MacAddrT for MacAddr {
    fn hex(&self) -> String {
        let mut out = format!("{:02x}", self[0]);
        for fld in &self[1..] {
            out.push_str(format!(":{:02x}", fld).as_str());
        }
        out
    }
}

impl Action {
    pub const fn detailed(&self) -> &str {
        match self {
            Self::ACT_TX_UNKNOWN => "Unknown action caused by a packet transmission.",
            Self::ACT_RX_UNKNOWN => "Unknown action caused by a packet reception.",
            Self::ACT_US_UNKNOWN => "Unknown action caused by command from user-space.",
            Self::ACT_TX_ADD => "A packet transmission caused a mesh path to be added (without a nexthop).",
            Self::ACT_TX_ADD_ASG => "A packet transmission caused a mesh path to be added (with a nexthop).",
            Self::ACT_TX_ASG => "A packet transmission caused the insertion of a nexthop to a mesh path that didn't have one.",
            Self::ACT_TX_CHG => "A packet transmission caused the update of a nexthop to a mesh path that already had one.",
            Self::ACT_TX_DEL => "A packet transmission caused a mesh path to be deleted.",
            Self::ACT_RX_ADD => "A packet reception caused a mesh path to be added (without a nexthop).",
            Self::ACT_RX_ADD_ASG => "A packet reception caused a mesh path to be added (with a nexthop).",
            Self::ACT_RX_ASG => "A packet reception caused the insertion of a nexthop to a mesh path that didn't have one.",
            Self::ACT_RX_CHG => "A packet reception caused the update of a nexthop to a mesh path that already had one.",
            Self::ACT_RX_DEL => "A packet reception caused a mesh path to be deleted.",
            Self::ACT_US_ADD => "A command from user-space caused a mesh path to be added (without a nexthop).",
            Self::ACT_US_ADD_ASG => "A command from user-space caused a mesh path to be added (with a nexthop).",
            Self::ACT_US_ASG => "A command from user-space caused the insertion of a nexthop to a mesh path that didn't have one.",
            Self::ACT_US_CHG => "A command from user-space caused the update of a nexthop to a mesh path that already had one.",
            Self::ACT_US_DEL => "A command from user-space caused a mesh path to be deleted.",
            Self::ACT_KR_EXP => "A mesh path was deleted because it expired.",
        }
    }
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::ACT_TX_UNKNOWN => "TX_UNKNOWN",
                Self::ACT_RX_UNKNOWN => "RX_UNKNOWN",
                Self::ACT_US_UNKNOWN => "US_UNKNOWN",
                Self::ACT_TX_ADD => "TX_ADD",
                Self::ACT_TX_ADD_ASG => "TX_ADD_ASG",
                Self::ACT_TX_ASG => "TX_ASG",
                Self::ACT_TX_CHG => "TX_CHG",
                Self::ACT_TX_DEL => "TX_DEL",
                Self::ACT_RX_ADD => "RX_ADD",
                Self::ACT_RX_ADD_ASG => "RX_ADD_ASG",
                Self::ACT_RX_ASG => "RX_ASG",
                Self::ACT_RX_CHG => "RX_CHG",
                Self::ACT_RX_DEL => "RX_DEL",
                Self::ACT_US_ADD => "US_ADD",
                Self::ACT_US_ADD_ASG => "US_ADD_ASG",
                Self::ACT_US_ASG => "US_ASG",
                Self::ACT_US_CHG => "US_CHG",
                Self::ACT_US_DEL => "US_DEL",
                Self::ACT_KR_EXP => "KR_EXP",
            }
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    id: usize,
    ts: SystemTime,
    pkts: Vec<usize>,
    action: Action,
    mac: MacAddr,
    iface: String,
    dst: MacAddr,
    old_nh: Option<MacAddr>,
    new_nh: Option<MacAddr>,
    frm_ctrl: u16,
    seq_ctrl: u16,
    qos_ctrl: Option<u16>,
    addr1: MacAddr,
    addr2: MacAddr,
    addr3: MacAddr,
    addr4: Option<MacAddr>,
}

impl Event {
    pub fn from_raw(raw: RawEvent, count: usize) -> Self {
        let (old_nh, new_nh) = match raw.action {
            Action::ACT_TX_ADD | Action::ACT_RX_ADD | Action::ACT_US_ADD => (None, None),
            Action::ACT_TX_UNKNOWN
            | Action::ACT_RX_UNKNOWN
            | Action::ACT_US_UNKNOWN
            | Action::ACT_TX_CHG
            | Action::ACT_RX_CHG
            | Action::ACT_US_CHG => (Some(raw.old_nh), Some(raw.new_nh)),
            Action::ACT_TX_ADD_ASG
            | Action::ACT_RX_ADD_ASG
            | Action::ACT_TX_ASG
            | Action::ACT_RX_ASG
            | Action::ACT_US_ADD_ASG
            | Action::ACT_US_ASG => (None, Some(raw.new_nh)),
            Action::ACT_TX_DEL | Action::ACT_RX_DEL | Action::ACT_US_DEL | Action::ACT_KR_EXP => {
                (if raw.has_nh { Some(raw.old_nh) } else { None }, None)
            }
        };

        let qos_ctrl = if raw.frm_ctrl & CHECK_QOS == HAS_QOS {
            Some(raw.qos_ctrl)
        } else {
            None
        };

        let addr4 = if raw.frm_ctrl & HAS_ADDR4 == HAS_ADDR4 {
            Some(raw.addr4)
        } else {
            None
        };

        Self {
            id: count,
            ts: BOOT_TIME
                .checked_add(Duration::from_nanos(raw.ts))
                .expect("add boot time to timestamp"),
            pkts: Vec::with_capacity(1),
            action: raw.action,
            mac: raw.mac,
            iface: unsafe {
                String::from_utf8_unchecked(raw.iface.to_vec())
                    .trim_matches('\0')
                    .to_owned()
            },
            dst: raw.dst,
            old_nh,
            new_nh,
            frm_ctrl: raw.frm_ctrl,
            seq_ctrl: raw.seq_ctrl,
            qos_ctrl,
            addr1: raw.addr1,
            addr2: raw.addr2,
            addr3: raw.addr3,
            addr4,
        }
    }

    pub fn push_packet(&mut self, counter: usize) {
        self.pkts.push(counter);
    }

    pub const fn id(&self) -> &usize {
        &self.id
    }

    pub const fn ts(&self) -> &SystemTime {
        &self.ts
    }

    pub fn pkts(&self) -> &[usize] {
        &self.pkts
    }

    pub const fn action(&self) -> &Action {
        &self.action
    }

    pub const fn mac(&self) -> &MacAddr {
        &self.mac
    }

    pub fn iface(&self) -> &str {
        &self.iface
    }

    pub const fn dst(&self) -> &MacAddr {
        &self.dst
    }

    pub const fn old_nh(&self) -> &Option<MacAddr> {
        &self.old_nh
    }

    pub const fn new_nh(&self) -> &Option<MacAddr> {
        &self.new_nh
    }

    pub const fn frm_ctrl(&self) -> &u16 {
        &self.frm_ctrl
    }

    pub const fn seq_ctrl(&self) -> &u16 {
        &self.seq_ctrl
    }

    pub const fn qos_ctrl(&self) -> &Option<u16> {
        &self.qos_ctrl
    }

    pub fn compare_addr1(&self, rhs: &[u8]) -> bool {
        Self::compare_addrs(&self.addr1, rhs)
    }

    pub fn compare_addr2(&self, rhs: &[u8]) -> bool {
        Self::compare_addrs(&self.addr2, rhs)
    }

    fn compare_addrs(lhs: &[u8], rhs: &[u8]) -> bool {
        if lhs == [0, 0, 0, 0, 0, 0] {
            true
        } else {
            lhs == rhs
        }
    }

    pub const fn from_pkt(&self) -> bool {
        matches!(
            self.action,
            Action::ACT_TX_ADD
                | Action::ACT_TX_ADD_ASG
                | Action::ACT_TX_ASG
                | Action::ACT_TX_CHG
                | Action::ACT_TX_DEL
                | Action::ACT_TX_UNKNOWN
                | Action::ACT_RX_ADD
                | Action::ACT_RX_ADD_ASG
                | Action::ACT_RX_ASG
                | Action::ACT_RX_CHG
                | Action::ACT_RX_DEL
                | Action::ACT_RX_UNKNOWN
        )
    }
}
