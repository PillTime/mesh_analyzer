mod util;
use crate::util::{
    create_ringbuffer, event_matches_packet, get_collected_data, initialize_events_file,
    load_bpf_program, setup_cli_arg_parser, start_packet_capture,
};

use std::{
    fs::File,
    io::Write,
    path::Path,
    process::exit,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use libbpf_rs::Error::System;
use libc::EINTR;
use pcap::{Error::NoMorePackets, Linktype};
use serde_json::to_string_pretty;
use signal_hook::{consts::TERM_SIGNALS, flag::register};

fn main() {
    // handle termination signals
    let stop = Arc::new(AtomicBool::new(false));
    for signal in TERM_SIGNALS {
        register(*signal, stop.clone()).expect("register terminate signals");
    }

    // get cli arguments
    let cli_args = setup_cli_arg_parser().get_matches();
    let station = cli_args
        .get_one::<String>("STATION")
        .expect("get station name from cli arguments")
        .clone();
    let interface = cli_args
        .get_one::<String>("INTERFACE")
        .expect("get interface from cli arguments")
        .clone();

    // create the filenames and filepaths
    let events_filename = format!("./{station}.json");
    let capture_filename = format!("./{station}.pcap");
    let events_filepath = Path::new(&events_filename);
    let capture_filepath = Path::new(&capture_filename);

    // stop by default if the files already exist
    if (events_filepath.exists() || capture_filepath.exists()) && !cli_args.contains_id("force") {
        println!(
            "Can't continue because the output files would overwrite existing ones. \
             Use --force to overwrite them."
        );
        exit(1);
    }

    // bpf initialization
    let events_file = initialize_events_file(events_filepath);
    let skeleton = load_bpf_program(cli_args.contains_id("debug"));
    let ringbuf = create_ringbuffer(&skeleton, events_file.clone());

    // packet capture
    start_packet_capture(stop.clone(), capture_filepath.to_path_buf(), interface);

    // bpf loop
    println!("Ready!");
    while !stop.load(Ordering::Relaxed) {
        match ringbuf.poll(Duration::from_millis(100)) {
            Ok(()) => {}
            Err(System(EINTR)) => break, // man 2 epoll_wait | ERRORS section
            Err(err) => panic!("{err:?}"),
        }
    }
    println!("\rStopping...");

    // finish the events file
    events_file
        .lock()
        .expect("lock events file to write the tail")
        .write_all(b"]\n")
        .expect("write events file tail");

    // get collected data
    let (mut events, mut packets) = get_collected_data(events_filepath, capture_filepath);
    let datalinktype = packets.get_datalink();
    assert_eq!(
        datalinktype,
        Linktype::IEEE802_11_RADIOTAP,
        "datalink is not ieee80211 radiotap (127), but is instead {datalinktype:?}"
    );

    // relate events and packets
    let mut counter = 0usize;
    loop {
        counter += 1;
        match packets.next() {
            Ok(pkt) => {
                if pkt.header.caplen != pkt.header.len {
                    eprintln!(
                        "packet {counter} skipped because not all of its contents are available"
                    );
                    continue;
                }
                for evt in &mut events {
                    if event_matches_packet(evt, pkt.data, pkt.header.caplen as usize) {
                        evt.push_packet(counter);
                    }
                }
            }
            Err(NoMorePackets) => break,
            Err(err) => {
                eprintln!("error on packet {counter}: {err:?}");
            }
        }
    }

    // rewrite the events file
    File::create(events_filepath)
        .expect("recreate events file")
        .write_all(
            to_string_pretty(&events)
                .expect("pretty serialize events")
                .as_bytes(),
        )
        .expect("2nd write of events file");

    println!("Done!");
}
