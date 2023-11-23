use std::{env, path, sync::Arc, fs, io::{self, BufRead}};
use rfd;
use sqlite::{self, ConnectionWithFullMutex};
use regex::Regex;

use yara::{self, Rules, Compiler, Scanner};

use android_sanity_checker::androidparser;

fn parse_path(path: String, connx: Arc<ConnectionWithFullMutex>, yara_checker: Arc<Vec<Rules>>) {
    let path = path::Path::new(path.as_str());
    let validator_flag = match path.try_exists() {
        Ok(x)=> x,
        Err(err) => panic!("[Error] {}", err.to_string()),
    };
    if validator_flag && path.is_dir() == true {
        if let Ok(read_dir) = path.read_dir() {
            rayon::scope(|s| {
                read_dir.into_iter().for_each(|each_dir| {
                    if let Ok(each_entry) = each_dir {
                        if each_entry.file_type().unwrap().is_dir() {
                            parse_path(String::from(each_entry.path().to_str().unwrap()), Arc::clone(&connx), yara_checker.clone()); 
                        }
                        else if each_entry.file_type().unwrap().is_file() && each_entry.path().extension().is_some_and(|x| x.to_str().unwrap() == "txt") {
                            let local_connx = connx.clone();
                            let mut vec_yara_scanner: Vec<Scanner> = vec![];
                            yara_checker.iter().for_each(|yara_rules| {
                                let mut yara_scanner = yara_rules.scanner().unwrap();
                                yara_scanner.set_timeout(10);
                                yara_scanner.set_flags(yara::ScanFlags::REPORT_RULES_MATCHING);
                                vec_yara_scanner.push(yara_scanner);
                            });
                            s.spawn(move |_| {
                                // println!("[DEBUT] {}", each_entry.file_name().to_str().unwrap());
                                let android_file_parser = androidparser::AndroidParser::new(each_entry.path().as_path());
                                match android_file_parser {
                                    Ok(x) => {
                                        x.go_parse(local_connx, vec_yara_scanner);
                                    },
                                    Err(err) => eprintln!("{err}"),
                                };
                                // println!("[FIN] {}", each_entry.file_name().to_str().unwrap());
                            });
                        }
                    }
                });
            });
        }
    }
    else if path.extension().is_some_and(|x| x.to_str().unwrap() == "txt") && validator_flag && path.is_file() {
        let android_file_parser = androidparser::AndroidParser::new(path);
        match android_file_parser {
            Ok(x) => {
                let mut vec_yara_scanner: Vec<Scanner> = vec![];
                yara_checker.iter().for_each(|yara_rules| {
                    let mut yara_scanner = yara_rules.scanner().unwrap();
                    yara_scanner.set_timeout(10);
                    yara_scanner.set_flags(yara::ScanFlags::REPORT_RULES_MATCHING);
                    vec_yara_scanner.push(yara_scanner);
                });
                x.go_parse(Arc::clone(&connx), vec_yara_scanner);
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

fn yara_rules_finder(path:String) -> Vec<String> {
    let path = path::Path::new(path.as_str());
    let validator_flag: bool = match path.try_exists() {
        Ok(x) => x,
        Err(err) => panic!("[Error] {}", err.to_string()),
    };
    let mut yara_rules_vec: Vec<String> = vec![];
    if validator_flag && path.is_dir() == true {
        if let Ok(read_dir) = path.read_dir() {
            read_dir.into_iter().for_each(|each_dir| {
                if let Ok(each_entry) = each_dir {
                    if each_entry.file_type().unwrap().is_dir() {
                        yara_rules_finder(each_entry.path().to_str().unwrap().to_string()).into_iter().for_each(|each_yara_rules_path| {
                            yara_rules_vec.push(each_yara_rules_path);
                        });
                    }
                    else if each_entry.file_type().unwrap().is_file() && (each_entry.path().extension().is_some_and(|x| x.to_str().unwrap() == "yar") || each_entry.path().extension().is_some_and(|x| x.to_str().unwrap() == "yara")) {
                        yara_rules_vec.push(each_entry.path().to_str().unwrap().to_string());
                    }
                }
            });
        }
    }
    yara_rules_vec
}

// fn yara_rules_ingester(paths: Vec<String>) -> Vec<Rules> {
fn yara_rules_ingester(paths: Vec<String>) -> Rules {
    // let mut compiled_ruleset: Vec<Rules> = vec![];
    let mut concat_rules = String::new();
    let mut ingested_rules: Vec<String> = vec![];
    let mut inval_rules_counter: u32 = 0;
    let mut skipped_rules_counter:u32 = 0;
    let overall_yara_files = paths.len();
    let re = match Regex::new(r"^((?P<global>global)\s)?rule\s+(?P<identifier>\S+)\s?.*?\{?$") {
        Ok(x) => x,
        Err(err) => panic!("{}", err),
    };
    // let mut compiler = Compiler::new().unwrap();
    paths.into_iter().for_each(|each_path| {
        // if let Ok(yara_compiler) = Compiler::new().unwrap().add_rules_file(each_path) {
        if let Ok(file_handler) = fs::OpenOptions::new().read(true).write(false).create(false).open(path::Path::new(each_path.as_str())) {
            let buf_reader = io::BufReader::new(file_handler);
            let mut crash_string = String::new();
            let mut crash_ingest_rules: Vec<String> = vec![];
            let mut valid_rule_flag: bool = false;
            buf_reader.lines().into_iter().for_each(|line| {
                match line {
                    Ok(l) => {
                        let captures = match re.captures(l.as_str()) {
                            Some(caps) => Some((caps.name("global").map_or("".to_string(), |m| String::from(m.as_str())),
                                                        caps.name("identifier").map_or("".to_string(), |m| String::from(m.as_str())))),
                            None => {
                                None
                            },
                        };
                        let _ = match captures {
                            Some(x) => {
                                if x.0.is_empty() {
                                    // Si pas global, je traite
                                    if !x.1.is_empty() {
                                        if crash_ingest_rules.contains(&x.1) || ingested_rules.contains(&x.1) {
                                            valid_rule_flag = false;
                                            println!("[SKIP] Duplicate identifier for rule {}", x.1);
                                            skipped_rules_counter += 1;
                                        }
                                        else {
                                            valid_rule_flag = true;
                                            crash_string.push_str(format!("{}\n", l.as_str()).as_str());
                                            crash_ingest_rules.push(x.1);
                                        }
                                        // Si  j'ai un rule identifier, je flag et je traite.
                                    }
                                }
                                else {
                                    valid_rule_flag = false;
                                    println!("[SKIP] rule {} is global", x.1.as_str());
                                    inval_rules_counter += 1;
                                }
                            },
                            None => {
                                if l.starts_with("import ") {
                                    crash_string.push_str(l.as_str());
                                }
                                if valid_rule_flag {
                                    if l.starts_with("/*") {
                                        valid_rule_flag = false;
                                    }
                                    else {
                                        crash_string.push_str(format!("{}\n", l.as_str()).as_str());
                                    }
                                }
                            },
                        };
                    },
                    Err(err) => println!("[ERROR] {}", err.to_string()),
                };
            });
            let yara_compiler = Compiler::new().unwrap().add_rules_str(&crash_string);
            match yara_compiler {
                Ok(yara_compiler) => {
                    let _ = match yara_compiler.compile_rules() {
                        Ok(_) => {
                            concat_rules.push_str(format!("{}\n", crash_string).as_str());
                            crash_ingest_rules.into_iter().for_each(|x| {
                                ingested_rules.push(x);
                            });
                        },
                        Err(err) => {
                            println!("[ERROR {}] on file => {}", err.kind.to_string(), each_path.as_str());
                            inval_rules_counter += 1;
                        },
                    };
                },
                Err(_) => {
                    println!("[ERROR Add Rules] => {}", each_path.as_str());
                    inval_rules_counter += 1;
                },
            };
        };
    });
    println!("Executed from {}", env::current_dir().unwrap().to_str().unwrap());
    println!("[REPORT] Skipped {}/{2} rule(s) file(s) containing duplicated.\n[REPORT] Skipped {}/{2} rule(s) file(s) containing error(s)", skipped_rules_counter, inval_rules_counter, overall_yara_files);
    let compiler = Compiler::new().unwrap();
    let _ = match compiler.add_rules_str(concat_rules.as_str()) {
        Ok(x) => {
            let _ = match x.compile_rules() {
                Ok(z) => return z,
                Err(err) => panic!("[ERROR] {}", err.kind.to_string()),
            };
        }
        Err(err) => panic!("[ERROR] {}", err.to_string()),
    };
}

fn main() {

    // !! FOR DEBUG !!
    env::set_var("RUST_BACKTRACE", "1");
    // !! FOR DEBUG !!

    // Building YARA Resource
    let yara_precompiled = include_bytes!("../resources/yara_precompiled.yara");
    // 

    let cursor_yara_precompiled = io::Cursor::new(yara_precompiled);
    let yara_default_rules = Rules::load_from_stream(cursor_yara_precompiled).unwrap();

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
        .pick_folder() {
        Some(f) => {
            println!("Finding & compiling YARA rules. Please wait...");
            vec![yara_rules_ingester(yara_rules_finder(f.to_str().unwrap().to_string())), yara_default_rules]
        },
        _ => {
            println!("No given Yara rules, will continue with known Yara rules.");
            vec![Compiler::new().unwrap().compile_rules().unwrap(), yara_default_rules]
        },
    };
    // let _ = yara_rules.save(format!("{}\\yara_precompiled.yara", env::current_dir().unwrap().to_str().unwrap()).as_str());

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
            parse_ref(String::from(d.to_str().unwrap()), Arc::clone(&connection));
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
            println!("Working on the Analyse. Please wait...");
            let yara_rules = Arc::new(yara_rules);
            parse_path(String::from(d.to_str().unwrap()), Arc::clone(&connection), Arc::clone(&yara_rules));
        },
        None => panic!("No directory selected."),
    };
    println!("Work done. Check into each device directory to find reports.");
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