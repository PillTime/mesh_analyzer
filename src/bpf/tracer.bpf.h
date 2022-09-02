#ifndef TRACER_BPF_H
#define TRACER_BPF_H

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>


#define ETH_ALEN 6  // <uapi/linux/if_ether.h>
#define IFNAMSIZ 16 // <uapi/linux/if.h>

// <linux/ieee80211.h>
#define IEEE80211_FCTL_FROMDS    0x0200
#define IEEE80211_FCTL_TODS      0x0100
#define IEEE80211_FCTL_FTYPE     0x000c
#define IEEE80211_FTYPE_DATA     0x0008
#define IEEE80211_STYPE_QOS_DATA 0x0080

// <linux/err.h>
#define MAX_ERRNO       4095
#define IS_ERR_VALUE(x) __builtin_expect(!!((x) >= (unsigned long)-MAX_ERRNO), 0)

static inline bool __attribute__((__warn_unused_result__))
IS_PTR_ERR_OR_NULL(const void *ptr)
{
    return __builtin_expect(!!(!ptr), 0) || IS_ERR_VALUE((unsigned long)ptr);
}

const u16 HAS_ADDR4 = IEEE80211_FCTL_TODS  | IEEE80211_FCTL_FROMDS;
const u16 HAS_QOS   = IEEE80211_FTYPE_DATA | IEEE80211_STYPE_QOS_DATA;
const u16 CHECK_QOS = IEEE80211_FCTL_FTYPE | IEEE80211_STYPE_QOS_DATA;

const size_t HDR_SIZE_3ADDR = sizeof(struct ieee80211_hdr_3addr);
const size_t HDR_SIZE_4ADDR = sizeof(struct ieee80211_hdr);


///// SITUATION ////////////////////////////////////////////////////////////////////////////////////

typedef enum Situation {
    SIT_ADD,
    SIT_ADD_ASG,
    SIT_ASG,
    SIT_CHG,
    SIT_DEL,
    SIT_EXP,
} Situation;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, Situation);
} situation_store SEC(".maps");


///// ACTION ///////////////////////////////////////////////////////////////////////////////////////

typedef enum Action {
    ACT_TX_UNKNOWN,
    ACT_RX_UNKNOWN,
    ACT_US_UNKNOWN,

    /// Transmission
    ACT_TX_ADD,
    ACT_TX_ADD_ASG,
    ACT_TX_ASG, // mesh_path_assign_nexthop() is never called from a TX function
    ACT_TX_CHG, // mesh_path_assign_nexthop() is never called from a TX function
    ACT_TX_DEL,

    /// Reception
    ACT_RX_ADD,
    ACT_RX_ADD_ASG,
    ACT_RX_ASG,
    ACT_RX_CHG,
    ACT_RX_DEL, // mesh_path_del() is never called from a RX function

    /// User-Space
    ACT_US_ADD, // can't add without a nexthop
    ACT_US_ADD_ASG,
    ACT_US_ASG,
    ACT_US_CHG,
    ACT_US_DEL,

    /// Kernel
    ACT_KR_EXP,
} Action;


///// EVENT ////////////////////////////////////////////////////////////////////////////////////////

typedef struct Event {
    /// Station Info
    u8 mac[ETH_ALEN];
    u8 iface[IFNAMSIZ];

    /// Action Info
    u64 ts;
    Action action;

    /// Path Info
    u8 dst[ETH_ALEN];
    u8 old_nh[ETH_ALEN];
    u8 new_nh[ETH_ALEN];
    bool has_nh; // only for del

    /// Packet Info
    u16 frm_ctrl;
    u16 seq_ctrl;
    u16 qos_ctrl;
    u8 addr1[ETH_ALEN];
    u8 addr2[ETH_ALEN];
    u8 addr3[ETH_ALEN];
    u8 addr4[ETH_ALEN];
} Event;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, Event);
} event_store SEC(".maps");


///// RING BUFFER //////////////////////////////////////////////////////////////////////////////////

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} ringbuf SEC(".maps");


#endif // TRACER_BPF_H
