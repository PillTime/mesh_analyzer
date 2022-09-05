mod gui;
mod util;

use crate::{
    gui::Gui,
    util::{get_files, setup_cli_arg_parser, Station},
};

use std::path::Path;

use eframe::{run_native, NativeOptions};

fn main() {
    let cli_args = setup_cli_arg_parser().get_matches();
    let folder = Path::new(
        cli_args
            .get_one::<String>("FOLDER")
            .expect("get folder from cli arguments"),
    );

    let stations = Station::stations_from_files(get_files(folder));

    run_native(
        "Mesh Analyzer",
        NativeOptions::default(),
        Box::new(|cc| Box::new(Gui::new(cc, stations))),
    );
}
