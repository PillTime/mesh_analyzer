pub mod event;

use crate::Action;

use std::{
    fmt::{Display, Formatter, Result},
    time::SystemTime,
};

use lazy_static::lazy_static;
use libc::ETH_ALEN;
use psutil::host::boot_time;
use serde::{Deserialize, Serialize};

lazy_static! {
    static ref BOOT_TIME: SystemTime = boot_time().expect("get system boot time");
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacAddr(pub(crate) [u8; ETH_ALEN as usize]);

impl Display for MacAddr {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        let mut out = format!("{:02x}", self.0[0]);
        for fld in &self.0[1..] {
            out.push_str(format!(":{:02x}", fld).as_str());
        }
        write!(f, "{out}")
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

impl Display for Action {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
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
