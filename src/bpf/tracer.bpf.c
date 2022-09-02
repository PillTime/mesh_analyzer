#include "tracer.bpf.h"

char LICENSE[] SEC("license") = "GPL";


///// IEEE80211_XMIT ///////////////////////////////////////////////////////////////////////////////

// transmission action
SEC("tp/net/net_dev_xmit")
int BPF_PROG(tx)
{
    u32 tid = (u32)bpf_get_current_pid_tgid();
    struct trace_event_raw_net_dev_xmit *args = (struct trace_event_raw_net_dev_xmit *)ctx;

    Event *event = bpf_map_lookup_elem(&event_store, &tid);
    Situation *situation = bpf_map_lookup_elem(&situation_store, &tid);
    if (event == NULL || situation == NULL) {
        bpf_map_delete_elem(&event_store, &tid);
        bpf_map_delete_elem(&situation_store, &tid);
        return 0;
    }

    Event *pass = bpf_ringbuf_reserve(&ringbuf, sizeof(Event), 0);
    if (pass == NULL) {
        bpf_map_delete_elem(&event_store, &tid);
        bpf_map_delete_elem(&situation_store, &tid);
        return 0;
    }

    pass->ts = event->ts;
    for (int i = 0; i < IFNAMSIZ; i++) pass->iface[i] = event->iface[i];
    for (int i = 0; i < ETH_ALEN; i++) {
        pass->mac[i] = event->mac[i];
        pass->dst[i] = event->dst[i];
        pass->old_nh[i] = event->old_nh[i];
        pass->new_nh[i] = event->new_nh[i];
    }

    switch (*situation) {
        case SIT_ADD:
            pass->action = ACT_TX_ADD;
            break;
        case SIT_ADD_ASG:
            pass->action = ACT_TX_ADD_ASG;
            break;
        case SIT_ASG:
            pass->action = ACT_TX_ASG;
            break;
        case SIT_CHG:
            pass->action = ACT_TX_CHG;
            break;
        case SIT_DEL:
            pass->action = ACT_TX_DEL;
            break;
        default:
            pass->action = ACT_TX_UNKNOWN;
    }

    struct sk_buff *skb;
    struct ieee80211_hdr *hdr;
    bpf_core_read(&skb, sizeof(struct sk_buff *), (struct sk_buff *)&args->skbaddr);
    bpf_core_read(&hdr, sizeof(struct ieee80211_hdr *), (struct ieee80211_hdr *)&skb->data);

    BPF_CORE_READ_INTO(&pass->frm_ctrl, hdr, frame_control);
    BPF_CORE_READ_INTO(&pass->seq_ctrl, hdr, seq_ctrl);

    BPF_CORE_READ_INTO(&pass->addr1, hdr, addr1);
    BPF_CORE_READ_INTO(&pass->addr2, hdr, addr2);
    BPF_CORE_READ_INTO(&pass->addr3, hdr, addr3);

    size_t hdr_sz;
    if ((pass->frm_ctrl & HAS_ADDR4) == HAS_ADDR4) {
        hdr_sz = HDR_SIZE_4ADDR;
        BPF_CORE_READ_INTO(&pass->addr4, hdr, addr4);
    } else {
        hdr_sz = HDR_SIZE_3ADDR;
    }
    if ((pass->frm_ctrl & CHECK_QOS) == HAS_QOS) {
        bpf_core_read(&pass->qos_ctrl, 2, (u8 *)hdr + hdr_sz);
    }

    bpf_ringbuf_submit(pass, 0);
    bpf_map_delete_elem(&event_store, &tid);
    bpf_map_delete_elem(&situation_store, &tid);
    return 0;
}


///// IEEE80211_MESH_RX_QUEUED_MGMT ////////////////////////////////////////////////////////////////

// reception action
SEC("fexit/ieee80211_mesh_rx_queued_mgmt")
int BPF_PROG (rx,
    struct ieee80211_sub_if_data *sdata,
    struct sk_buff *skb
) {
    u32 tid = (u32)bpf_get_current_pid_tgid();

    Event *event = bpf_map_lookup_elem(&event_store, &tid);
    Situation *situation = bpf_map_lookup_elem(&situation_store, &tid);
    if (event == NULL || situation == NULL) {
        bpf_map_delete_elem(&event_store, &tid);
        bpf_map_delete_elem(&situation_store, &tid);
        return 0;
    }

    Event *pass = bpf_ringbuf_reserve(&ringbuf, sizeof(Event), 0);
    if (pass == NULL) {
        bpf_map_delete_elem(&event_store, &tid);
        bpf_map_delete_elem(&situation_store, &tid);
        return 0;
    }

    pass->ts = event->ts;
    for (int i = 0; i < IFNAMSIZ; i++) pass->iface[i] = event->iface[i];
    for (int i = 0; i < ETH_ALEN; i++) {
        pass->mac[i] = event->mac[i];
        pass->dst[i] = event->dst[i];
        pass->old_nh[i] = event->old_nh[i];
        pass->new_nh[i] = event->new_nh[i];
    }

    switch (*situation) {
        case SIT_ADD:
            pass->action = ACT_RX_ADD;
            break;
        case SIT_ADD_ASG:
            pass->action = ACT_RX_ADD_ASG;
            break;
        case SIT_ASG:
            pass->action = ACT_RX_ASG;
            break;
        case SIT_CHG:
            pass->action = ACT_RX_CHG;
            break;
        case SIT_DEL:
            pass->action = ACT_RX_DEL;
            break;
        default:
            pass->action = ACT_RX_UNKNOWN;
    }

    struct ieee80211_hdr *hdr;
    bpf_core_read(&hdr, sizeof(struct ieee80211_hdr *), (struct ieee80211_hdr *)&skb->data);

    BPF_CORE_READ_INTO(&pass->frm_ctrl, hdr, frame_control);
    BPF_CORE_READ_INTO(&pass->seq_ctrl, hdr, seq_ctrl);

    BPF_CORE_READ_INTO(&pass->addr1, hdr, addr1);
    BPF_CORE_READ_INTO(&pass->addr2, hdr, addr2);
    BPF_CORE_READ_INTO(&pass->addr3, hdr, addr3);

    size_t hdr_sz;
    if ((pass->frm_ctrl & HAS_ADDR4) == HAS_ADDR4) {
        hdr_sz = HDR_SIZE_4ADDR;
        BPF_CORE_READ_INTO(&pass->addr4, hdr, addr4);
    } else {
        hdr_sz = HDR_SIZE_3ADDR;
    }
    if ((pass->frm_ctrl & CHECK_QOS) == HAS_QOS) {
        bpf_core_read(&pass->qos_ctrl, 2, (u8 *)hdr + hdr_sz);
    }

    bpf_ringbuf_submit(pass, 0);
    bpf_map_delete_elem(&event_store, &tid);
    bpf_map_delete_elem(&situation_store, &tid);
    return 0;
}


///// RDEV_RETURN_INT //////////////////////////////////////////////////////////////////////////////

// user-space action
SEC("tp/cfg80211/rdev_return_int")
int BPF_PROG(us)
{
    u32 tid = (u32)bpf_get_current_pid_tgid();

    Event *event = bpf_map_lookup_elem(&event_store, &tid);
    Situation *situation = bpf_map_lookup_elem(&situation_store, &tid);
    if (event == NULL || situation == NULL) {
        bpf_map_delete_elem(&event_store, &tid);
        bpf_map_delete_elem(&situation_store, &tid);
        return 0;
    }

    Event *pass = bpf_ringbuf_reserve(&ringbuf, sizeof(Event), 0);
    if (pass == NULL) {
        bpf_map_delete_elem(&event_store, &tid);
        bpf_map_delete_elem(&situation_store, &tid);
        return 0;
    }

    pass->ts = event->ts;
    for (int i = 0; i < IFNAMSIZ; i++) pass->iface[i] = event->iface[i];
    for (int i = 0; i < ETH_ALEN; i++) {
        pass->mac[i] = event->mac[i];
        pass->dst[i] = event->dst[i];
        pass->old_nh[i] = event->old_nh[i];
        pass->new_nh[i] = event->new_nh[i];
    }

    switch (*situation) {
        case SIT_ADD:
            pass->action = ACT_US_ADD;
            break;
        case SIT_ADD_ASG:
            pass->action = ACT_US_ADD_ASG;
            break;
        case SIT_ASG:
            pass->action = ACT_US_ASG;
            break;
        case SIT_CHG:
            pass->action = ACT_US_CHG;
            break;
        case SIT_DEL:
            pass->action = ACT_US_DEL;
            break;
        default:
            pass->action = ACT_US_UNKNOWN;
    }

    bpf_ringbuf_submit(pass, 0);
    bpf_map_delete_elem(&event_store, &tid);
    bpf_map_delete_elem(&situation_store, &tid);
    return 0;
}


///// MESH_PATH_EXPIRE /////////////////////////////////////////////////////////////////////////////

// paths expired, set situation so that __mesh_path_del() does the submitting
SEC("fentry/mesh_path_expire")
int BPF_PROG(kr_exp_in)
{
    u32 tid = (u32)bpf_get_current_pid_tgid();

    // entry/expire should always be the first call
    // if anything already in the store, delete and overwrite it
    Situation init_situation = SIT_EXP, *situation = &init_situation;

    bpf_map_delete_elem(&event_store, &tid);
    bpf_map_update_elem(&situation_store, &tid, situation, BPF_ANY);
    return 0;
}

// done submitting expirations, remove the situation
SEC("fexit/mesh_path_expire")
int BPF_PROG(kr_exp_out)
{
    u32 tid = (u32)bpf_get_current_pid_tgid();

    // could do a safety check here to see if situation is still SIT_EXP,
    // but whether it still is or not, the procedure is the same,
    // delete this thread's contents from the maps

    bpf_map_delete_elem(&event_store, &tid);
    bpf_map_delete_elem(&situation_store, &tid);
    return 0;
}


///// MESH_PATH_ADD ////////////////////////////////////////////////////////////////////////////////

// can use the return value to see if the add was successfull
// documentation says it returns 0 on success but that's incorrect
SEC("fexit/mesh_path_add")
int BPF_PROG(add,
    struct ieee80211_sub_if_data *sdata,
    u8 *dst,
    struct mesh_path *ret
) {
    u32 tid = (u32)bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();

    // check if return value is an error or null
    if (ret == NULL || IS_ERR_VALUE((unsigned long)ret)) {
        return 0;
    }

    // add should always be the first call
    // if anything already in the store, ignore and overwrite it
    // (but shouldn't happen anyway)
    Event init_event = {0}, *event = &init_event;
    Situation init_situation = SIT_ADD, *situation = &init_situation;

    event->ts = ts;
    BPF_CORE_READ_INTO(&event->dst, ret, dst);
    BPF_CORE_READ_INTO(&event->mac, sdata, vif.addr);
    BPF_CORE_READ_STR_INTO(&event->iface, sdata, name);

    bpf_map_update_elem(&event_store, &tid, event, BPF_ANY);
    bpf_map_update_elem(&situation_store, &tid, situation, BPF_ANY);
    return 0;
}


///// MESH_PATH_ASSIGN_NEXTHOP /////////////////////////////////////////////////////////////////////

// need to check entry to see the old nexthop
// no use in checking the exit since it doesn't return
SEC("fentry/mesh_path_assign_nexthop")
int BPF_PROG(asg_chg,
    struct mesh_path *mpath,
    struct sta_info *sta
) {
    u32 tid = (u32)bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();

    Event init_event = {0}, *event;
    Situation init_situation = SIT_ASG, *situation;

    event = bpf_map_lookup_elem(&event_store, &tid);
    situation = bpf_map_lookup_elem(&situation_store, &tid);

    if ((event == NULL) != (situation == NULL)) {
        bpf_map_delete_elem(&event_store, &tid);
        bpf_map_delete_elem(&situation_store, &tid);
        return 0;
    } else if (event == NULL) {
        // asg or chg (use the init event since there's nothing in the map)
        event = &init_event;
    } else {
        // add_asg (reset the situation)
        init_situation = SIT_ADD_ASG;
    }
    situation = &init_situation;

    event->ts = ts;
    BPF_CORE_READ_INTO(&event->new_nh, sta, addr);

    if (*situation != SIT_ADD_ASG) {
        if (mpath->next_hop != NULL) {
            *situation = SIT_CHG;
            BPF_CORE_READ_INTO(&event->old_nh, mpath, next_hop, addr);
        }
        BPF_CORE_READ_INTO(&event->dst, mpath, dst);
        BPF_CORE_READ_INTO(&event->mac, mpath, sdata, vif.addr);
        BPF_CORE_READ_STR_INTO(&event->iface, mpath, sdata, name);
    }

    bpf_map_update_elem(&event_store, &tid, event, BPF_ANY);
    bpf_map_update_elem(&situation_store, &tid, situation, BPF_ANY);
    return 0;
}


///// __MESH_PATH_DEL //////////////////////////////////////////////////////////////////////////////

// checking exit even though it doesn't return because of the order of calls
//   ('mesh_path_del' calls '__mesh_path_del' several times, but we only need to register once,
//    and we only want the info from the last call)
SEC("fexit/__mesh_path_del")
int BPF_PROG(del_out,
    struct mesh_table *tbl,
    struct mesh_path *mpath
) {
    u32 tid = (u32)bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();

    Event init_event = {0}, *event;
    Situation init_situation = SIT_DEL, *situation;

    event = bpf_map_lookup_elem(&event_store, &tid);
    situation = bpf_map_lookup_elem(&situation_store, &tid);

    // expiration of paths (return at the end of if statement)
    if (situation != NULL && *situation == SIT_EXP) {
        Event *pass = bpf_ringbuf_reserve(&ringbuf, sizeof(Event), 0);
        if (pass == NULL) {
            return 0;
        }

        pass->ts = ts;
        pass->action = ACT_KR_EXP;
        BPF_CORE_READ_INTO(&pass->dst, mpath, dst);
        BPF_CORE_READ_INTO(&pass->mac, mpath, sdata, vif.addr);
        BPF_CORE_READ_STR_INTO(&pass->iface, mpath, sdata, name);

        if (mpath->next_hop != NULL) {
            pass->has_nh = true;
            BPF_CORE_READ_INTO(&pass->old_nh, mpath, next_hop, addr);
        } else {
            pass->has_nh = false;
        }

        bpf_ringbuf_submit(pass, 0);
        return 0;
    }

    // normal deletion
    event = &init_event;
    situation = &init_situation;

    event->ts = ts;
    BPF_CORE_READ_INTO(&event->dst, mpath, dst);
    BPF_CORE_READ_INTO(&event->mac, mpath, sdata, vif.addr);
    BPF_CORE_READ_STR_INTO(&event->iface, mpath, sdata, name);

    if (mpath->next_hop != NULL) {
        event->has_nh = true;
        BPF_CORE_READ_INTO(&event->old_nh, mpath, next_hop, addr);
    } else {
        event->has_nh = false;
    }

    bpf_map_update_elem(&event_store, &tid, event, BPF_ANY);
    bpf_map_update_elem(&situation_store, &tid, situation, BPF_ANY);
    return 0;
}


///// MESH_PLINK_DEACTIVATE ////////////////////////////////////////////////////////////////////////

// ignoring everything from plink because the number of possible call stacks is too high
//   (would take too much time and too many probes to separate into the different reasons,
//    so we'll just ignore them, since they're less likely to be the cause for an action anyway)
SEC("fexit/mesh_plink_deactivate")
int BPF_PROG(plink)
{
    u32 tid = (u32)bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&event_store, &tid);
    bpf_map_delete_elem(&situation_store, &tid);
    return 0;
}
