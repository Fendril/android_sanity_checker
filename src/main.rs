use std::{env, path};
use rfd;
use sqlite;

use android_sanity_checker::androidparser;

fn parse_path(path: &path::Path, connx: &sqlite::Connection) {
    let validator_flag = match path.try_exists() {
        Ok(x)=> x,
        Err(err) => panic!("[Error] {}", err.to_string()),
    };
    if validator_flag & path.is_dir() == true {
        if let Ok(read_dir) = path.read_dir() {
            for each_dir in read_dir {
                if let Ok(each_entry) = each_dir {
                    parse_path(each_entry.path().as_path(), connx);
                }
            }
        }
    }
    else if validator_flag & path.is_file() == true {
        let android_file_parser = androidparser::AndroidParser::new(path);
        match android_file_parser {
            Ok(x) => x.go_parse(connx),
            Err(err) => eprintln!("{err}"),
        };
    }
}

fn parse_ref(path: &path::Path, connx: &sqlite::Connection) {
    let validator_flag = match path.try_exists() {
        Ok(x)=> x,
        Err(err) => panic!("[Error] {}", err.to_string()),
    };
    if validator_flag & path.is_dir() == true {
        if let Ok(read_dir) = path.read_dir() {
            for each_dir in read_dir {
                if let Ok(each_entry) = each_dir {
                    parse_ref(each_entry.path().as_path(), connx);
                }
            }
        }
    }
    else if validator_flag & path.is_file() == true {
        let android_file_parser = androidparser::AndroidParser::new(path);
        match android_file_parser {
            Ok(x) => x.go_ref(connx),
            Err(err) => eprintln!("{err}"),
        };
    }
}

    // if let Ok(read_dir) = path_to_dir.read_dir() {
    //     for each_dir in read_dir {
    //         if let Ok(each_dir) = each_dir {
    //             let this_dir_path = each_dir.path();
    //             let this_dir = path::Path::new(this_dir_path.to_str().unwrap());
    //             if each_dir.file_type().unwrap().is_dir() {
    //                 // TODO: Gestion de Threads
    //                 parse_dir(&this_dir);
    //             }
    //             else if each_dir.file_type().unwrap().is_file() {
    //                 let buf_reader = get_reader_ro(this_dir);
    //                 android_file_selector(this_dir, buf_reader);
    //             }
    //         }
    //     }
    // }

fn main() {

    // !! FOR DEBUG !!
    env::set_var("RUST_BACKTRACE", "1");
    // !! FOR DEBUG !!

    let connection = sqlite::open(":memory:");
    // let connection = sqlite::open(r"D:\Experimentations\Android\test.sqlite");
    let connection = match connection {
        Ok(x) => x,
        Err(err) => panic!("{err}"),
    };

    let user_entries: Vec<String> = env::args().skip(1).map(|x| String::from(x)).collect();
    for argument in user_entries {
        if argument.starts_with("--threads=") {
            let available_threads = num_cpus::get();
            let user_entry = match &argument[10..].parse::<usize>(){
                Ok(x) => if available_threads < *x { available_threads } else { *x },
                Err(_) => panic!("Number of threads must be a number --> --threads=4"),
            };
            println!("User -> {} | Available -> {}", user_entry, available_threads);
        } else {
            parse_path(path::Path::new(argument.as_str()), &connection);
        }
    }
    let tip_message: rfd::AsyncMessageDialog = rfd::AsyncMessageDialog::new()
            .set_title("Information")
            .set_description("Choose Reference directory")
            .set_buttons(rfd::MessageButtons::Ok);
    let _ = tip_message.show();
    let _dir = match rfd::FileDialog::new()
            .set_directory("/")
            .pick_folder() {
        Some(d) => {
            println!("Creating reference into SQLite DB. Please wait...");
            parse_ref(d.as_path(), &connection)
        },
        None => panic!("No directory selected."),
    };
    let tip_message: rfd::AsyncMessageDialog = rfd::AsyncMessageDialog::new()
            .set_title("Information")
            .set_description("Choose directory to Analyze")
            .set_buttons(rfd::MessageButtons::Ok);
    let _ = tip_message.show();
    let _dir = match rfd::FileDialog::new()
            .set_directory("/")
            .pick_folder() {
        Some(d) => parse_path(d.as_path(), &connection),
        None => panic!("No directory selected."),
    };
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