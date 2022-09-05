use crate::util::Station;

use mesh_analyzer::{Event, MacAddr};

use std::{
    cell::RefCell,
    collections::HashMap,
    process::{Child, Command},
    sync::Mutex,
};

use eframe::{
    egui::{
        CentralPanel, CollapsingHeader, Context, Direction, Grid, Layout, RichText, ScrollArea,
        Style, Ui, Visuals, Window,
    },
    emath::Align,
    glow::Context as GlowContext,
    App, CreationContext, Frame,
};
use egui_extras::{Size, TableBuilder};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

pub struct Gui {
    stations: Vec<Station>,
    events_windows_open: RefCell<HashMap<(String, usize), bool>>,
    wireshark_open: RefCell<HashMap<String, Mutex<Child>>>,
}

impl Gui {
    pub fn new(cc: &CreationContext, stations: Vec<Station>) -> Self {
        cc.egui_ctx.set_style(Style {
            visuals: Visuals::dark(),
            ..Style::default()
        });
        let mut events_windows_open =
            HashMap::with_capacity(stations[0].events().len() * stations.len());
        for station in &stations {
            let name = station.name();
            for (i, event) in station.events().iter().enumerate() {
                if event.is_some() {
                    events_windows_open.insert((name.to_string(), i), false);
                }
            }
        }
        Self {
            stations,
            events_windows_open: RefCell::new(events_windows_open),
            wireshark_open: RefCell::new(HashMap::default()),
        }
    }

    fn gui_table(&mut self, ui: &mut Ui) {
        let num_stations = self.stations.len();
        let num_events = self.stations[0].events().len();
        TableBuilder::new(ui)
            .striped(true)
            .cell_layout(Layout::centered_and_justified(Direction::LeftToRight))
            .column(Size::exact(50.0))
            .columns(
                Size::remainder().at_least(150.0).at_most(250.0),
                num_stations,
            )
            .header(25.0, |mut head| {
                head.col(|ui| {
                    ui.heading(RichText::new("Time").strong());
                });
                for station in &self.stations {
                    head.col(|ui| {
                        ui.heading(RichText::new(station.name()).strong());
                    });
                }
            })
            .body(|body| {
                body.rows(36.0, num_events, |i, mut row| {
                    row.col(|ui| {
                        ui.label(RichText::new(format!("{}", i + 1)).size(20.0).strong());
                    });
                    for station in &self.stations {
                        row.col(|ui| {
                            ui.horizontal(|ui| {
                                let event = station.events()[i].as_ref();
                                if let Some(event) = event {
                                    ui.label(RichText::new(event.id().to_string()).size(20.0));
                                    ui.with_layout(Layout::left_to_right(), |ui| {
                                        ui.vertical(|ui| {
                                            ui.with_layout(
                                                Layout::top_down_justified(Align::Center),
                                                |ui| {
                                                    ui.label(format!(
                                                        "{} ({})",
                                                        event.action(),
                                                        self.name_from_mac(event.dst())
                                                    ));
                                                    if ui.button("Info").clicked() {
                                                        self.events_windows_open
                                                            .borrow_mut()
                                                            .insert(
                                                                (station.name().to_string(), i),
                                                                true,
                                                            );
                                                    }
                                                },
                                            );
                                        });
                                    });
                                }
                            });
                        });
                    }
                });
            });
    }

    fn gui_window_grid(&self, ui: &mut Ui, station: &Station, event: &Event) {
        Grid::new(format!("{}_{}", station.name(), event.id()))
            .striped(true)
            .show(ui, |ui| {
                ui.label("Action:");
                ui.label(event.action().to_string())
                    .on_hover_text(event.action().detailed());
                ui.end_row();
                ui.label("Interface:");
                ui.label(format!("{} [{}]", event.iface(), event.mac(),));
                ui.end_row();
                ui.label("Timestamp:");
                ui.label(
                    OffsetDateTime::from(*event.ts())
                        .format(&Rfc3339)
                        .expect("format timestamp"),
                );
                ui.end_row();
                ui.label("Path information:");
                ui.end_row();
                ui.label("\t\tDestination:");
                ui.label(format!(
                    "{} [{}]",
                    self.name_from_mac(event.dst()),
                    event.dst()
                ));
                ui.end_row();
                if let Some(nh) = event.old_nh() {
                    ui.label("\t\tOld nexthop:");
                    ui.label(format!("{} [{}]", self.name_from_mac(nh), nh));
                    ui.end_row();
                }
                if let Some(nh) = event.new_nh() {
                    ui.label("\t\tNew nexthop:");
                    ui.label(format!("{} [{}]", self.name_from_mac(nh), nh));
                    ui.end_row();
                }
            });
    }

    fn name_from_mac(&self, mac: &MacAddr) -> &str {
        for station in &self.stations {
            if station.mac().contains(mac) {
                return station.name();
            }
        }
        "???"
    }
}

impl App for Gui {
    fn on_exit(&mut self, _gl: &GlowContext) {
        #[allow(unused_must_use)]
        for wireshark in self.wireshark_open.borrow().iter() {
            wireshark
                .1
                .lock()
                .expect("get lock on wireshark child (exit)")
                .kill();
        }
    }

    fn update(&mut self, ctx: &Context, _frame: &mut Frame) {
        CentralPanel::default().show(ctx, |ui| {
            ScrollArea::horizontal().show(ui, |ui| {
                self.gui_table(ui);
            });
        });
        for window in self.events_windows_open.borrow_mut().iter_mut() {
            let mut station = None;
            let mut event = None;
            for sta in &self.stations {
                if sta.name() == window.0 .0 {
                    station = Some(sta);
                    event = sta.events()[window.0 .1].as_ref();
                    break;
                }
            }
            if station.is_none() || event.is_none() {
                continue;
            }
            let station = station.unwrap();
            let event = event.unwrap();

            Window::new(format!("Station {} | Event {}", station.name(), event.id()))
                .resizable(false)
                .open(window.1)
                .show(ctx, |ui| {
                    self.gui_window_grid(ui, station, event);
                    if event.from_pkt() {
                        ui.separator();
                        ui.with_layout(Layout::top_down(Align::Center), |ui| {
                            if event.pkts().is_empty() {
                                ui.label("This event doesn't have any packets associated to it, even though it should.");
                                if ui.button("Open capture file in Wireshark anyway").clicked() {
                                    #[allow(unused_must_use)]
                                    if let Some(chl) = self.wireshark_open.borrow_mut().get_mut(station.name()) {
                                        chl.get_mut().expect("get lock on wireshark child (1)").kill();
                                    }
                                    self.wireshark_open.borrow_mut().insert(station.name().to_string(), Mutex::new(
                                        Command::new("wireshark")
                                            .args([
                                                "-r",
                                                &station.pcap().to_string_lossy()
                                            ])
                                            .spawn()
                                            .expect("start wireshark (1)")
                                        ));
                                }
                            } else if event.pkts().len() == 1 {
                                if ui.button("Open event in Wireshark").clicked() {
                                    #[allow(unused_must_use)]
                                    if let Some(chl) = self.wireshark_open.borrow_mut().get_mut(station.name()) {
                                        chl.get_mut().expect("get lock on wireshark child (2)").kill();
                                    }
                                    self.wireshark_open.borrow_mut().insert(station.name().to_string(), Mutex::new(

                                    Command::new("wireshark").args([
                                        "-r",
                                        &station.pcap().to_string_lossy(),
                                        "-g",
                                        &event.pkts()[0].to_string(),
                                    ]).spawn().expect("start wireshark (2)")
                                    ));
                                }
                            } else {
                                ui.label("This event has several packets associated to it (should be only one):");
                                CollapsingHeader::new("Packets").show(ui, |ui| {
                                    for pkt in event.pkts() {
                                        ui.label(pkt.to_string());
                                    }
                                });
                                if ui.button("Open Wireshark at the first event").clicked() {
                                    #[allow(unused_must_use)]
                                    if let Some(chl) = self.wireshark_open.borrow_mut().get_mut(station.name()) {
                                        chl.get_mut().expect("get lock on wireshark child (3)").kill();
                                    }
                                    self.wireshark_open.borrow_mut().insert(station.name().to_string(), Mutex::new(

                                    Command::new("wireshark").args([
                                        "-r",
                                        &station.pcap().to_string_lossy(),
                                        "-g",
                                        &event.pkts()[0].to_string(),
                                    ]).spawn().expect("start wireshark (3)")
                                    ));
                                }
                            }
                        });
                    }
                });
        }
    }
}
