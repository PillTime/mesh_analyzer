/* automatically generated by rust-bindgen 0.60.1 */

use serde::{Deserialize, Serialize};

pub type __u8 = ::std::os::raw::c_uchar;
pub type __u16 = ::std::os::raw::c_ushort;
pub type u8_ = __u8;
pub type u16_ = __u16;
pub type __kernel_ulong_t = ::std::os::raw::c_ulong;
pub type __kernel_size_t = __kernel_ulong_t;
pub type size_t = __kernel_size_t;
pub const HAS_ADDR4: u16_ = 768;
pub const HAS_QOS: u16_ = 136;
pub const CHECK_QOS: u16_ = 140;
pub const HDR_SIZE_3ADDR: size_t = 24;
pub const HDR_SIZE_4ADDR: size_t = 30;
#[repr(u32)]
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq, Deserialize, Serialize)]
pub enum Action {
    ACT_TX_UNKNOWN = 0,
    ACT_RX_UNKNOWN = 1,
    ACT_US_UNKNOWN = 2,
    ACT_TX_ADD = 3,
    ACT_TX_ADD_ASG = 4,
    ACT_TX_ASG = 5,
    ACT_TX_CHG = 6,
    ACT_TX_DEL = 7,
    ACT_RX_ADD = 8,
    ACT_RX_ADD_ASG = 9,
    ACT_RX_ASG = 10,
    ACT_RX_CHG = 11,
    ACT_RX_DEL = 12,
    ACT_US_ADD = 13,
    ACT_US_ADD_ASG = 14,
    ACT_US_ASG = 15,
    ACT_US_CHG = 16,
    ACT_US_DEL = 17,
    ACT_KR_EXP = 18,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct Event {
    pub mac: [u8_; 6usize],
    pub iface: [u8_; 16usize],
    pub action: Action,
    pub dst: [u8_; 6usize],
    pub old_nh: [u8_; 6usize],
    pub new_nh: [u8_; 6usize],
    pub frm_ctrl: u16_,
    pub seq_ctrl: u16_,
    pub qos_ctrl: u16_,
    pub addr1: [u8_; 6usize],
    pub addr2: [u8_; 6usize],
    pub addr3: [u8_; 6usize],
    pub addr4: [u8_; 6usize],
}
#[test]
fn bindgen_test_layout_Event() {
    assert_eq!(
        ::std::mem::size_of::<Event>(),
        76usize,
        concat!("Size of: ", stringify!(Event))
    );
    assert_eq!(
        ::std::mem::align_of::<Event>(),
        4usize,
        concat!("Alignment of ", stringify!(Event))
    );
    fn test_field_mac() {
        assert_eq!(
            unsafe {
                let uninit = ::std::mem::MaybeUninit::<Event>::uninit();
                let ptr = uninit.as_ptr();
                ::std::ptr::addr_of!((*ptr).mac) as usize - ptr as usize
            },
            0usize,
            concat!(
                "Offset of field: ",
                stringify!(Event),
                "::",
                stringify!(mac)
            )
        );
    }
    test_field_mac();
    fn test_field_iface() {
        assert_eq!(
            unsafe {
                let uninit = ::std::mem::MaybeUninit::<Event>::uninit();
                let ptr = uninit.as_ptr();
                ::std::ptr::addr_of!((*ptr).iface) as usize - ptr as usize
            },
            6usize,
            concat!(
                "Offset of field: ",
                stringify!(Event),
                "::",
                stringify!(iface)
            )
        );
    }
    test_field_iface();
    fn test_field_action() {
        assert_eq!(
            unsafe {
                let uninit = ::std::mem::MaybeUninit::<Event>::uninit();
                let ptr = uninit.as_ptr();
                ::std::ptr::addr_of!((*ptr).action) as usize - ptr as usize
            },
            24usize,
            concat!(
                "Offset of field: ",
                stringify!(Event),
                "::",
                stringify!(action)
            )
        );
    }
    test_field_action();
    fn test_field_dst() {
        assert_eq!(
            unsafe {
                let uninit = ::std::mem::MaybeUninit::<Event>::uninit();
                let ptr = uninit.as_ptr();
                ::std::ptr::addr_of!((*ptr).dst) as usize - ptr as usize
            },
            28usize,
            concat!(
                "Offset of field: ",
                stringify!(Event),
                "::",
                stringify!(dst)
            )
        );
    }
    test_field_dst();
    fn test_field_old_nh() {
        assert_eq!(
            unsafe {
                let uninit = ::std::mem::MaybeUninit::<Event>::uninit();
                let ptr = uninit.as_ptr();
                ::std::ptr::addr_of!((*ptr).old_nh) as usize - ptr as usize
            },
            34usize,
            concat!(
                "Offset of field: ",
                stringify!(Event),
                "::",
                stringify!(old_nh)
            )
        );
    }
    test_field_old_nh();
    fn test_field_new_nh() {
        assert_eq!(
            unsafe {
                let uninit = ::std::mem::MaybeUninit::<Event>::uninit();
                let ptr = uninit.as_ptr();
                ::std::ptr::addr_of!((*ptr).new_nh) as usize - ptr as usize
            },
            40usize,
            concat!(
                "Offset of field: ",
                stringify!(Event),
                "::",
                stringify!(new_nh)
            )
        );
    }
    test_field_new_nh();
    fn test_field_frm_ctrl() {
        assert_eq!(
            unsafe {
                let uninit = ::std::mem::MaybeUninit::<Event>::uninit();
                let ptr = uninit.as_ptr();
                ::std::ptr::addr_of!((*ptr).frm_ctrl) as usize - ptr as usize
            },
            46usize,
            concat!(
                "Offset of field: ",
                stringify!(Event),
                "::",
                stringify!(frm_ctrl)
            )
        );
    }
    test_field_frm_ctrl();
    fn test_field_seq_ctrl() {
        assert_eq!(
            unsafe {
                let uninit = ::std::mem::MaybeUninit::<Event>::uninit();
                let ptr = uninit.as_ptr();
                ::std::ptr::addr_of!((*ptr).seq_ctrl) as usize - ptr as usize
            },
            48usize,
            concat!(
                "Offset of field: ",
                stringify!(Event),
                "::",
                stringify!(seq_ctrl)
            )
        );
    }
    test_field_seq_ctrl();
    fn test_field_qos_ctrl() {
        assert_eq!(
            unsafe {
                let uninit = ::std::mem::MaybeUninit::<Event>::uninit();
                let ptr = uninit.as_ptr();
                ::std::ptr::addr_of!((*ptr).qos_ctrl) as usize - ptr as usize
            },
            50usize,
            concat!(
                "Offset of field: ",
                stringify!(Event),
                "::",
                stringify!(qos_ctrl)
            )
        );
    }
    test_field_qos_ctrl();
    fn test_field_addr1() {
        assert_eq!(
            unsafe {
                let uninit = ::std::mem::MaybeUninit::<Event>::uninit();
                let ptr = uninit.as_ptr();
                ::std::ptr::addr_of!((*ptr).addr1) as usize - ptr as usize
            },
            52usize,
            concat!(
                "Offset of field: ",
                stringify!(Event),
                "::",
                stringify!(addr1)
            )
        );
    }
    test_field_addr1();
    fn test_field_addr2() {
        assert_eq!(
            unsafe {
                let uninit = ::std::mem::MaybeUninit::<Event>::uninit();
                let ptr = uninit.as_ptr();
                ::std::ptr::addr_of!((*ptr).addr2) as usize - ptr as usize
            },
            58usize,
            concat!(
                "Offset of field: ",
                stringify!(Event),
                "::",
                stringify!(addr2)
            )
        );
    }
    test_field_addr2();
    fn test_field_addr3() {
        assert_eq!(
            unsafe {
                let uninit = ::std::mem::MaybeUninit::<Event>::uninit();
                let ptr = uninit.as_ptr();
                ::std::ptr::addr_of!((*ptr).addr3) as usize - ptr as usize
            },
            64usize,
            concat!(
                "Offset of field: ",
                stringify!(Event),
                "::",
                stringify!(addr3)
            )
        );
    }
    test_field_addr3();
    fn test_field_addr4() {
        assert_eq!(
            unsafe {
                let uninit = ::std::mem::MaybeUninit::<Event>::uninit();
                let ptr = uninit.as_ptr();
                ::std::ptr::addr_of!((*ptr).addr4) as usize - ptr as usize
            },
            70usize,
            concat!(
                "Offset of field: ",
                stringify!(Event),
                "::",
                stringify!(addr4)
            )
        );
    }
    test_field_addr4();
}