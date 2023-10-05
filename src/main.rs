use std::{env, path, sync::Arc};
use rfd;
use sqlite::{self, ConnectionWithFullMutex};

use yara::{self, Rules};

use android_sanity_checker::androidparser;

fn parse_path(path: String, connx: Arc<ConnectionWithFullMutex>, yara_checker: Option<Arc<Rules>>) {
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
                        let local_yara_checker = yara_checker.clone();
                        if each_entry.file_type().unwrap().is_dir() {
                            if let Some(local_yara_checker) = local_yara_checker {
                                parse_path(String::from(each_entry.path().to_str().unwrap()), Arc::clone(&connx), Some(local_yara_checker)); 
                            }
                            else {
                                parse_path(String::from(each_entry.path().to_str().unwrap()), Arc::clone(&connx), None); 
                            }
                        }
                        else if each_entry.file_type().unwrap().is_file() && each_entry.path().extension().is_some_and(|x| x.to_str().unwrap() == "txt") {
                            let local_connx = connx.clone();
                            s.spawn(move |_| {
                                // println!("[DEBUT] {}", each_entry.file_name().to_str().unwrap());
                                let android_file_parser = androidparser::AndroidParser::new(each_entry.path().as_path());
                                match android_file_parser {
                                    Ok(x) => {
                                        if let Some(local_yara_checker) = local_yara_checker {
                                            x.go_parse(local_connx, Some(local_yara_checker));
                                        }
                                        else {
                                            x.go_parse(local_connx, None);    
                                        }
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
                if let Some(local_yara_checker) = yara_checker {
                    x.go_parse(Arc::clone(&connx), Some(local_yara_checker));
                }
                else {
                    x.go_parse(Arc::clone(&connx), None);    
                }
            },
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
    let connection: Arc<ConnectionWithFullMutex> = match connection {
        Ok(x) => Arc::new(x),
        Err(err) => panic!("{err}"),
    };

    let user_entries: Vec<String> = env::args().skip(1).map(|x| String::from(x)).collect();
    for argument in user_entries {
        println!("Passed arg : {}", argument);
    }

    let tip_message: rfd::MessageDialog = rfd::MessageDialog::new()
            .set_title("Information")
            .set_description("Optionnal : Choose a YARA rules file.")
            .set_buttons(rfd::MessageButtons::Ok);
    let _ = tip_message.show();
    let yara_rules = match rfd::FileDialog::new()
        .set_directory("/")
        .pick_file() {
        Some(f) => {
            let yara_compiler = yara::Compiler::new();
            if let Ok(yara_compiler) = yara_compiler {
                if let Ok(yara_compiler) = yara_compiler.add_rules_file(f.as_path()) {
                    if let Ok(yara_rules) = yara_compiler.compile_rules() {
                        Some(Arc::new(yara_rules))
                    }
                    else {
                        None
                    }
                }
                else {
                    None
                }
            }
            else {
                None
            }
        },
        None => None,
    };

    let tip_message: rfd::MessageDialog = rfd::MessageDialog::new()
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
    let tip_message: rfd::MessageDialog = rfd::MessageDialog::new()
            .set_title("Information")
            .set_description("Choose directory to Analyze")
            .set_buttons(rfd::MessageButtons::Ok);
    let _ = tip_message.show();
    let _dir = match rfd::FileDialog::new()
            .set_directory("/")
            .pick_folder() {
        Some(d) => {
            if let Some(yara_rules) = yara_rules {
                parse_path(String::from(d.to_str().unwrap()), Arc::clone(&connection), Some(Arc::clone(&yara_rules)));
            }
            else {
                parse_path(String::from(d.to_str().unwrap()), Arc::clone(&connection), None);
            }
        },
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