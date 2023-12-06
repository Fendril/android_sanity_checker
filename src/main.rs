use std::{env::current_dir, time::Instant};
use rfd;
use indicatif::HumanDuration;
use console::style;

use android_sanity_checker::androidparser::AndroidParser;

fn main() {

    // !! FOR DEBUG !!
    // env::set_var("RUST_BACKTRACE", "1");
    // !! FOR DEBUG !!

    let tip_message: rfd::MessageDialog = rfd::MessageDialog::new()
            .set_title("Information")
            .set_description("Optionnal : Choose a YARA rules file.")
            .set_buttons(rfd::MessageButtons::Ok);
    let _ = tip_message.show();
    let yara_rules = match rfd::FileDialog::new()
        .set_directory("/")
        .pick_folder() {
        Some(f) => {
            println!("{} YARA folder => {}",
                    style("[1/6]").bold().dim(),
                    f.to_str().unwrap()
            );
            Some(String::from(f.to_str().unwrap()))
        },
        _ => {
            println!("{} No given Yara rules, will continue with known Yara rules.",
                    style("[1/6]").bold().dim()
            );
            None
        },
    };

    // To Build a Yara precompiled uncomment below
    // let _ = yara_rules.save(format!("{}\\yara_precompiled.yara", env::current_dir().unwrap().to_str().unwrap()).as_str());
    //

    let tip_message: rfd::MessageDialog = rfd::MessageDialog::new()
            .set_title("Information")
            .set_description("Choose Reference directory")
            .set_buttons(rfd::MessageButtons::Ok);
    let _ = tip_message.show();
    let ref_dir = match rfd::FileDialog::new()
            .set_directory("/")
            .pick_folder() {
        Some(d) => {
            println!("{} Reference folder => {}",
                    style("[2/6]").bold().dim(),
                    d.to_str().unwrap()
            );
            String::from(d.to_str().unwrap())
        },
        None => panic!("[ABORT] No reference directory selected."),
    };
    let tip_message: rfd::MessageDialog = rfd::MessageDialog::new()
            .set_title("Information")
            .set_description("Choose directory to Analyze")
            .set_buttons(rfd::MessageButtons::Ok);
    let _ = tip_message.show();
    let analysis_dir = match rfd::FileDialog::new()
            .set_directory("/")
            .pick_folder() {
        Some(d) => {
            println!("{} Analysis directory => {}",
                style("[3/6]").bold().dim(),
                d.to_str().unwrap()
        );
            String::from(d.to_str().unwrap())
        },
        None => panic!("[ABORT] No analysis directory selected."),
    };
    match yara_rules {
        Some(_) => println!("{} Finding & compiling YARA rules.\n\tPlease wait...",
                style("[4/6]").bold().dim()
        ),
        None => println!("{} Loading default Yara Rules.\n\t Please wait...",
                style("[4/6]").bold().dim()
        ),
    };
    let start_global = Instant::now();
    if let Ok(android_parser) = AndroidParser::new(ref_dir,
            analysis_dir,
            yara_rules
    ){
        let mut start_step = Instant::now();
        println!("{} Creating reference into SQLite DB.\n\tPlease wait...",
                style("[5/6]").bold().dim()
        );
        android_parser.go_ref();
        println!("Creating reference duration : {}",
                HumanDuration(start_step.elapsed())
        );
        start_step = Instant::now();
        println!("{} Working on the Analyse.\n\tPlease wait...",
                style("[6/6]").bold().dim()
        );
        android_parser.go_parse();
        println!("Analysis duration : {}",
                HumanDuration(start_step.elapsed())
        );
    }
    println!("Global duration : {}",
          HumanDuration(start_global.elapsed())
    );
    println!("[Work done]\nCheck into each device directory to find reports.\nAlso check at {}\\reported_yara_matches.csv to find yara matches.", current_dir().unwrap().to_str().unwrap());
    // MainWindow::new().unwrap().run().unwrap();
}

// slint::slint! {

//     component MemoryTile inherits Rectangle {
//         width: 64px;
//         height: 64px;
//         background: #3960D5;

//         Image {
//             source: @image-url("icons/bus.png");
//             width: parent.width;
//             height: parent.height;
//         }
//     }

//     export component MainWindow inherits Window {
//         MemoryTile {}
//     }
// }