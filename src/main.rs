use std::{env, path, sync::Arc};
use rfd;
use sqlite::{self, ConnectionWithFullMutex};

use android_sanity_checker::androidparser;

fn parse_path(path: String, connx: Arc<ConnectionWithFullMutex>) {
    let path = path::Path::new(path.as_str());
    let validator_flag = match path.try_exists() {
        Ok(x)=> x,
        Err(err) => panic!("[Error] {}", err.to_string()),
    };
    if validator_flag && path.is_dir() == true {
        if let Ok(read_dir) = path.read_dir() {
            rayon::scope(|s| {
                for each_dir in read_dir {
                    if let Ok(each_entry) = each_dir {
                        if each_entry.file_type().unwrap().is_dir() {
                            parse_path(String::from(each_entry.path().to_str().unwrap()), Arc::clone(&connx)); 
                        }
                        else if each_entry.file_type().unwrap().is_file() && each_entry.path().extension().is_some_and(|x| x.to_str().unwrap() == "txt") {
                            let local_connx = connx.clone();
                            s.spawn(move |_| {
                                // println!("[DEBUT] {}", each_entry.file_name().to_str().unwrap());
                                let android_file_parser = androidparser::AndroidParser::new(each_entry.path().as_path());
                                match android_file_parser {
                                    Ok(x) => {
                                        x.go_parse(local_connx);
                                    },
                                    Err(err) => eprintln!("{err}"),
                                };
                                // println!("[FIN] {}", each_entry.file_name().to_str().unwrap());
                            });
                        }
                    }
                }
            });
        }
    }
    else if path.extension().is_some_and(|x| x.to_str().unwrap() == "txt") && validator_flag && path.is_file() {
        let android_file_parser = androidparser::AndroidParser::new(path);
        match android_file_parser {
            Ok(x) => {x.go_parse(Arc::clone(&connx));},
            Err(err) => eprintln!("{err}"),
        };
    }
}

fn parse_ref(path: String, connx: Arc<ConnectionWithFullMutex>) {
    let path = path::Path::new(path.as_str());
    let validator_flag = match path.try_exists() {
        Ok(x)=> x,
        Err(err) => panic!("[Error] {}", err.to_string()),
    };
    // println!("DEBUG {}", path.display());
    // println!("{} | {} | {}", path.extension().is_some_and(|x| x.to_str().unwrap() == "txt"), validator_flag, path.is_file());
    if validator_flag && path.is_dir() == true {
        if let Ok(read_dir) = path.read_dir() {
            rayon::scope(|s| {
                for each_dir in read_dir {
                    if let Ok(each_entry) = each_dir {
                        if each_entry.file_type().unwrap().is_dir() {
                            parse_ref(String::from(each_entry.path().to_str().unwrap()), Arc::clone(&connx)); 
                        }
                        else if each_entry.file_type().unwrap().is_file() && each_entry.path().extension().is_some_and(|x| x.to_str().unwrap() == "txt") {
                            let local_connx = connx.clone();
                            s.spawn(move |_| {
                                // println!("[DEBUT] {}", each_entry.file_name().to_str().unwrap());
                                let android_file_parser = androidparser::AndroidParser::new(each_entry.path().as_path());
                                match android_file_parser {
                                    Ok(x) => {
                                        x.go_ref(local_connx);
                                    },
                                    Err(err) => eprintln!("{err}"),
                                };
                                // println!("[FIN] {}", each_entry.file_name().to_str().unwrap());
                            });
                        }
                    }
                }
            });
        }
    }
    else if path.extension().is_some_and(|x| x.to_str().unwrap() == "txt") && validator_flag && path.is_file() {
        let android_file_parser = androidparser::AndroidParser::new(path);
        match android_file_parser {
            Ok(x) => {
                rayon::scope(|s| {
                    s.spawn(|_| {
                        x.go_ref(Arc::clone(&connx));
                    });
                });
            },
            Err(err) => eprintln!("{err}"),
        };
    }
}

fn main() {

    // !! FOR DEBUG !!
    env::set_var("RUST_BACKTRACE", "1");
    // !! FOR DEBUG !!

    let connection = sqlite::Connection::open_with_full_mutex(":memory:");
    // let connection = sqlite::Connection::open_with_full_mutex(r"D:\Experimentations\Android\test.sqlite");
    let connection: ConnectionWithFullMutex = match connection {
        Ok(x) => x,
        Err(err) => panic!("{err}"),
    };

    let connection = Arc::new(connection);

    let user_entries: Vec<String> = env::args().skip(1).map(|x| String::from(x)).collect();
    for argument in user_entries {
        if argument.starts_with("--threads=") {
            let available_threads = num_cpus::get();
            let user_entry = match &argument[10..].parse::<usize>(){
                Ok(x) => if available_threads < *x { available_threads } else { *x },
                Err(_) => panic!("Number of threads must be a number --> --threads=4"),
            };
            println!("User -> {} | Available -> {}", user_entry, available_threads);
            // POOL.set_num_threads(user_entry);
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
            parse_ref(String::from(d.to_str().unwrap()), Arc::clone(&connection))
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
        Some(d) => parse_path(String::from(d.to_str().unwrap()), Arc::clone(&connection)),
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