use super::BOOT_TIME;

use crate::{Action, MacAddr, RawEvent, CHECK_QOS, HAS_ADDR4, HAS_QOS};

use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

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
    // transform a `RawEvent` into an `Event`
    pub fn from_raw(raw: RawEvent, count: usize) -> Self {
        let (old_nh, new_nh) = match raw.action {
            Action::ACT_TX_ADD | Action::ACT_RX_ADD | Action::ACT_US_ADD => (None, None),
            Action::ACT_TX_UNKNOWN
            | Action::ACT_RX_UNKNOWN
            | Action::ACT_US_UNKNOWN
            | Action::ACT_TX_CHG
            | Action::ACT_RX_CHG
            | Action::ACT_US_CHG => (Some(MacAddr(raw.old_nh)), Some(MacAddr(raw.new_nh))),
            Action::ACT_TX_ADD_ASG
            | Action::ACT_RX_ADD_ASG
            | Action::ACT_TX_ASG
            | Action::ACT_RX_ASG
            | Action::ACT_US_ADD_ASG
            | Action::ACT_US_ASG => (None, Some(MacAddr(raw.new_nh))),
            Action::ACT_TX_DEL | Action::ACT_RX_DEL | Action::ACT_US_DEL | Action::ACT_KR_EXP => (
                if raw.has_nh {
                    Some(MacAddr(raw.old_nh))
                } else {
                    None
                },
                None,
            ),
        };

        let qos_ctrl = if raw.frm_ctrl & CHECK_QOS == HAS_QOS {
            Some(raw.qos_ctrl)
        } else {
            None
        };

        let addr4 = if raw.frm_ctrl & HAS_ADDR4 == HAS_ADDR4 {
            Some(MacAddr(raw.addr4))
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
            mac: MacAddr(raw.mac),
            iface: unsafe {
                String::from_utf8_unchecked(raw.iface.to_vec())
                    .trim_matches('\0')
                    .to_owned()
            },
            dst: MacAddr(raw.dst),
            old_nh,
            new_nh,
            frm_ctrl: raw.frm_ctrl,
            seq_ctrl: raw.seq_ctrl,
            qos_ctrl,
            addr1: MacAddr(raw.addr1),
            addr2: MacAddr(raw.addr2),
            addr3: MacAddr(raw.addr3),
            addr4,
        }
    }

    #[inline]
    pub fn push_packet(&mut self, counter: usize) {
        self.pkts.push(counter);
    }

    #[inline]
    pub const fn id(&self) -> &usize {
        &self.id
    }

    #[inline]
    pub const fn ts(&self) -> &SystemTime {
        &self.ts
    }

    #[inline]
    pub fn pkts(&self) -> &[usize] {
        &self.pkts
    }

    #[inline]
    pub const fn action(&self) -> &Action {
        &self.action
    }

    #[inline]
    pub const fn mac(&self) -> &MacAddr {
        &self.mac
    }

    #[inline]
    pub fn iface(&self) -> &str {
        &self.iface
    }

    #[inline]
    pub const fn dst(&self) -> &MacAddr {
        &self.dst
    }

    #[inline]
    pub const fn old_nh(&self) -> &Option<MacAddr> {
        &self.old_nh
    }

    #[inline]
    pub const fn new_nh(&self) -> &Option<MacAddr> {
        &self.new_nh
    }

    #[inline]
    pub const fn frm_ctrl(&self) -> &u16 {
        &self.frm_ctrl
    }

    #[inline]
    pub const fn seq_ctrl(&self) -> &u16 {
        &self.seq_ctrl
    }

    #[inline]
    pub const fn qos_ctrl(&self) -> &Option<u16> {
        &self.qos_ctrl
    }

    pub fn compare_addr1(&self, rhs: &[u8]) -> bool {
        Self::compare_addrs(&self.addr1.0, rhs)
    }

    pub fn compare_addr2(&self, rhs: &[u8]) -> bool {
        Self::compare_addrs(&self.addr2.0, rhs)
    }

    fn compare_addrs(lhs: &[u8], rhs: &[u8]) -> bool {
        if lhs == [0, 0, 0, 0, 0, 0] {
            true
        } else {
            lhs == rhs
        }
    }

    // check if an event was created because of a packet with the `action` field
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
