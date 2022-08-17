#!/usr/bin/env bash
# verified with shellcheck

MESH_ID='tester'
MESH_FREQ=2412

show_usage() {
    printf 'USAGE:\n    %s <STATION> <INTERFACE> <IP_SUFFIX> <SERVICE>\n\n' "$(basename "$0")"
    printf 'ARGS:\n    <STATION>      Name for the station.\n'
    printf '    <INTERFACE>    Network interface to be used in mesh network.\n'
    printf '    <IP_SUFFIX>    Value of the last block of the mesh IP address.\n'
    printf '    <SERVICE>      The executable file for tracing.\n'
}

bad_usage() {
    printf 'Bad usage. %s. Check -h/--help.\n' "$1"
    exit 1
}

check_capabilities() {
    PHY="phy$(iw dev "$MESH_IFACE" info | awk '/wiphy/{print $2}')"
    iw phy "$PHY" info | awk '/Supported interface modes/{flag=1;next} !/*/{flag=0}flag' | grep -qi 'mesh'
    support_mesh=$?
    iw phy "$PHY" info | awk '/software interface modes/{flag=1;next} !/*/{flag=0}flag' | grep -qi 'monitor'
    support_monitor=$?
    terminate=0
    if [ $support_mesh -ne 0 ]; then
        printf "Interface %s doesn't support mesh.\n" "$MESH_INTERFACE"
        terminate=1
    fi
    if [ $support_monitor -ne 0 ]; then
        printf "Interface %s doesn't support monitor.\n" "$MESH_INTERFACE"
        terminate=1
    fi
    if [ $terminate -ne 0 ]; then
        exit 1
    fi
}

create_monitor() {
    sudo iw phy "$PHY" interface add "$MON_IFACE" type monitor
    sudo ifconfig "$MON_IFACE" up
}

start_mesh() {
    sudo ifconfig "$MESH_IFACE" down
    sudo iw dev "$MESH_IFACE" set type mesh
    sudo ip addr add dev "$MESH_IFACE" "192.168.50.$IP_SUF/24"
    sudo ifconfig "$MESH_IFACE" up
    sudo iw dev "$MESH_IFACE" mesh join $MESH_ID freq $MESH_FREQ HT40+
}

run_tracer() {
    eval sudo "$EXEC $STATION $MON_IFACE"
}

stop_mesh() {
    sudo iw dev "$MESH_IFACE" mesh leave
    sudo ifconfig "$MESH_IFACE" down
    sudo ip addr flush dev "$MESH_IFACE"
}

delete_monitor() {
    sudo ifconfig "$MON_IFACE" down
    sudo iw dev "$MON_IFACE" del
}

case $1 in
    '-h'|'--help')
        show_usage
        exit 0
        ;;
esac

if [ $# -ne 4 ]; then
    bad_usage 'The script requires 4 arguments'
fi

STATION="$1"
MON_IFACE="$1-mon"
MESH_IFACE="$2"
PHY=''
IP_SUF="$3"
EXEC=$(realpath "$4")

check_capabilities
create_monitor \
&& start_mesh \
&& run_tracer
stop_mesh
delete_monitor
