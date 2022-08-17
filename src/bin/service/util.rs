#![allow(clippy::cast_ptr_alignment)]
#![allow(clippy::cast_possible_truncation)]

use mesh_analyzer::{
    Event, RawEvent, TracerSkel, TracerSkelBuilder, CHECK_QOS, HAS_ADDR4, HAS_QOS, HDR_SIZE_3ADDR,
    HDR_SIZE_4ADDR,
};

use std::{
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
    ptr::read,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    thread,
    time::SystemTime,
};

use byteorder::{ByteOrder, LittleEndian};
use clap::{App, Arg, Command};
use libbpf_rs::{RingBuffer, RingBufferBuilder};
use pcap::{Capture, Offline};
use serde_json::{from_slice, to_string};

pub fn setup_cli_arg_parser() -> App<'static> {
    Command::new("Mesh Analyzer - Service")
        .author("Carlos Pinto <up201606191@up.pt>")
        .arg(
            Arg::new("STATION")
                .required(true)
                .help("Name to be used for the output files."),
        )
        .arg(
            Arg::new("INTERFACE")
                .required(true)
                .help("Network interface to use for packet capture."),
        )
        .arg(
            Arg::new("force")
                .short('f')
                .long("force")
                .help("Overwrite output files if they already exist."),
        )
        .arg(
            Arg::new("debug")
                .short('d')
                .long("debug")
                .help("Show debug information from the eBPF program."),
        )
}

pub fn initialize_events_file(filepath: &Path) -> Arc<Mutex<File>> {
    let file = Arc::new(Mutex::new(
        File::create(filepath).expect("create event file"),
    ));
    file.lock()
        .expect("lock events file to write the head")
        .write_all(b"[")
        .expect("write events file head");
    file
}

// load the bpf program
pub fn load_bpf_program(verbose: bool) -> TracerSkel<'static> {
    let mut skel_builder = TracerSkelBuilder::default();
    skel_builder.obj_builder.debug(verbose);
    let skel_opened = skel_builder.open().expect("open the skeleton");
    let mut skel = skel_opened.load().expect("load the skeleton");
    skel.attach().expect("attach the skeleton");
    skel
}

// create the ringbuffer to get data from the kernel
pub fn create_ringbuffer(skel: &TracerSkel, events: Arc<Mutex<File>>) -> RingBuffer {
    let counter = Arc::new(AtomicUsize::new(1));
    let mut ringbuf_builder = RingBufferBuilder::new();
    ringbuf_builder
        .add(skel.maps().ringbuf(), move |data| {
            // callback function
            // parse raw bytes into an Event struct and save in the events file
            let count = counter.fetch_add(1, Ordering::SeqCst);
            let event_struct = Event::from_raw(
                unsafe { read(data.as_ptr().cast::<RawEvent>()) },
                count,
                SystemTime::now(),
            );
            let event_serialized = if count == 1 {
                to_string(&event_struct).expect("serialize event")
            } else {
                format!(",{}", to_string(&event_struct).expect("serialize event"))
            };
            events
                .lock()
                .expect("lock events file to write event")
                .write_all(event_serialized.as_bytes())
                .expect("write event to events file");
            0
        })
        .expect("add callback for ringbuffer");
    ringbuf_builder.build().expect("create ringbuffer")
}

// capture network packets in another thread
pub fn start_packet_capture(stop: Arc<AtomicBool>, capture_file: PathBuf, interface: String) {
    thread::spawn(move || {
        let mut pcap = Capture::from_device(interface.as_str())
            .expect("create capture")
            .immediate_mode(true)
            .timeout(100)
            .rfmon(true)
            .promisc(true)
            .open()
            .expect("activate capture")
            .setnonblock()
            .expect("set capture to nonblock");
        let mut file = pcap.savefile(capture_file).expect("create capture file");
        while !stop.load(Ordering::Relaxed) {
            if let Ok(pkt) = pcap.next() {
                file.write(&pkt);
            }
        }
    });
}

// read data from files
// (we save in files while capturing just in case something crashes)
pub fn get_collected_data(
    events_file: &Path,
    capture_file: &Path,
) -> (Vec<Event>, Capture<Offline>) {
    let mut events = vec![];
    File::open(events_file)
        .expect("open events file")
        .read_to_end(&mut events)
        .expect("read events file");
    let events = from_slice::<Vec<Event>>(&events).expect("deserialize events file");
    let capture = Capture::from_file(capture_file).expect("open packet capture file");
    (events, capture)
}

// match packets to events
pub fn event_matches_packet(event: &Event, data: &[u8], len: usize) -> bool {
    if len < 4 {
        return false;
    }

    // get the length of layer 1 and check that the first two bytes of layer 2 can be read
    let layer1_len = LittleEndian::read_u16(&data[2..=3]) as usize;
    if len <= layer1_len + 1 {
        return false;
    }

    // reposition the 'data' "pointer"
    let data = &data[layer1_len..];

    // get the length of layer 2 and make sure we have access to everything we need
    let frm_ctrl = LittleEndian::read_u16(&data[0..=1]);
    let layer2_len = if frm_ctrl & HAS_ADDR4 == HAS_ADDR4 {
        HDR_SIZE_4ADDR
    } else {
        HDR_SIZE_3ADDR
    } as usize
        + if frm_ctrl & CHECK_QOS == HAS_QOS {
            2 // qos section is 2 bytes
        } else {
            0 // no qos
        };
    if layer1_len + layer2_len > len {
        return false;
    }

    // finally safe, get everything else
    let seq_ctrl = LittleEndian::read_u16(&data[22..=23]);
    let qos_ctrl = if frm_ctrl & CHECK_QOS == HAS_QOS {
        Some(LittleEndian::read_u16(&data[(layer2_len - 2)..layer2_len]))
    } else {
        None
    };
    let addr1 = &data[4..=9];
    let addr2 = &data[10..=15];

    frm_ctrl == event.frm_ctrl()
        && seq_ctrl == event.seq_ctrl()
        && qos_ctrl == event.qos_ctrl()
        && event.compare_addr1(addr1)
        && event.compare_addr2(addr2)
}
