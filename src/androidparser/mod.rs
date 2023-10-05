use std::{io::{self, BufRead, Error, Write}, fs, path, sync:: Arc};
use regex::Regex;
use sqlite::{self, ConnectionWithFullMutex, State};
use yara::Rules;

pub struct AndroidParser {
    path_filename: String,
}

impl AndroidParser {

    pub fn new(get_this_file: &path::Path) -> Result<Self, Error> {
        match get_this_file.try_exists() {
            Ok(true) => {
                let path_filename = String::from(get_this_file.to_str().unwrap());
                return Ok(Self {path_filename})
            },
            Ok(false) => return Err(Error::new(io::ErrorKind::NotFound, "File not Found")),
            Err(err) => return Err(err),
        };
    }

    pub fn go_parse(&self, connx: Arc<ConnectionWithFullMutex>, yara_checker: Option<Arc<Rules>>){
        let buf_reader = self.create_bufreader();
        if let Ok(x) = buf_reader {
            self.android_file_selector(x, connx, yara_checker);
        }
    }

    pub fn go_ref(&self, connx: Arc<ConnectionWithFullMutex>) {
        let buf_reader = self.create_bufreader();
        if let Ok(x) = buf_reader {
            self.android_file_reference(x, connx);
        }
    }

    fn create_bufreader(&self) -> Result<io::BufReader<fs::File>, Error> {
        let file_handler = fs::OpenOptions::new().read(true).write(false).create(false).open(path::Path::new(&self.path_filename));
        match file_handler {
            Ok(x) => return Ok(io::BufReader::new(x)),
            Err(err) => return Err(err),
        };
    }

    fn create_bufwriter(&self) -> Result<io::BufWriter<fs::File>, Error> {
        let re = match regex::Regex::new(r"^(?P<REPORTPATH>\w:\\.*\\).*\\(?P<REPORTNAME>.*)\.txt$") {
            Ok(x) => x,
            Err(err) => panic!("{}", err),
        };
        if let Some(caps) = re.captures(self.path_filename.as_str()) {
            let report_filename = format!("{}{}.csv", caps.name("REPORTPATH").map_or("".to_string(), |m| String::from(m.as_str())), 
                                                                caps.name("REPORTNAME").map_or("".to_string(), |m| String::from(m.as_str())));
            let file = match fs::OpenOptions::new().read(true).write(true).append(true).create(true).open(path::Path::new(report_filename.as_str())) {
                Ok(x) => x,
                Err(err) => panic!("{}", err),
            };
            return Ok(io::BufWriter::new(file))
        }
        else {
            return Err(Error::new(io::ErrorKind::InvalidData, "Error occured while creating the File buffer to write report"))
        }
        // return Err(Error::new(io::ErrorKind::InvalidData, "Error occured while creating the File buffer to write report"))
    }

    fn create_key_value_table_ref(&self, connx: Arc<ConnectionWithFullMutex>, table_to_create: String, entries: Vec<(String, String)>, ) {
        let query_table = format!("CREATE TABLE '{}' (key TEXT, value TEXT)", table_to_create);
        let _ = connx.execute(query_table);
        let query_insert = format!("INSERT INTO '{}' (key, value) VALUES (:key, :value)", table_to_create);
        let mut statement = connx.prepare(query_insert).unwrap();
        entries.iter().for_each(|couple| {
            let _ = statement.bind(&[
                (":key", couple.0.as_str()),
                (":value", couple.1.as_str()),
            ][..]);
            while let Ok(State::Row) = statement.next() {}
            let _ = statement.reset();
        });
    }

    fn compare_key_value(&self, connx: Arc<ConnectionWithFullMutex>, yara_checker: Option<Arc<Rules>>, entries: Vec<(String, String)>, table_to_select: String) {
        let query = format!("SELECT * FROM '{}' WHERE key=:key", table_to_select);
        let mut stmt = connx.prepare(query.as_str()).unwrap();
        let mut buf_writer = match self.create_bufwriter() {
            Ok(x) => x,
            Err(err) => panic!("{}", err),
        };
        let _ = buf_writer.write_all("file_name;setting_name;setting_config;yara_match;yara_rulename\n".as_bytes());
        entries.into_iter().for_each(|each_entry| {
            let _ = stmt.bind((":key", each_entry.0.as_str()));
            let mut flag: bool = false;
            while let Ok(State::Row) = stmt.next() {
                let value: String = stmt.read(1).unwrap();
                if value == each_entry.1.to_string() {
                    flag = true;
                }
            }
            let _ = stmt.reset();
            if !flag {
                let mut matched_rules_names = String::new();
                flag = false;
                if let Some(yara_checker) = &yara_checker {
                    if let Ok(yara_matches) = yara_checker.scan_mem(format!("{} {}", each_entry.0, each_entry.1).as_bytes(), 5){
                        if !yara_matches.is_empty() {
                            if !flag { flag = true; }
                            yara_matches.into_iter().for_each(|x| {
                                matched_rules_names.push_str(format!("[{}]", x.identifier).as_str());
                            });
                        }
                    };
                };
                if flag {
                    let _ = buf_writer.write_all(format!("{};{};{};true;{}\n", self.path_filename.as_str(), each_entry.0, each_entry.1, matched_rules_names.as_str()).as_bytes());
                }
                else {
                    let _ = buf_writer.write_all(format!("{};{};{};false;\n", self.path_filename.as_str(), each_entry.0, each_entry.1).as_bytes());
                }
            }
        });
    }
    
    fn create_key_xvalues_table_ref(&self,connx: Arc<ConnectionWithFullMutex>, table_to_create: String, entries: Vec<Vec<(String, Vec<String>)>>) {
        let query_table = format!("CREATE TABLE '{}' (key TEXT, value TEXT)", table_to_create);
        let _ = connx.execute(query_table);
        let query_insert = format!("INSERT INTO '{}' (key, value) VALUES (:key, :value)", table_to_create);
        let mut statement = connx.prepare(query_insert).unwrap();
        entries.into_iter().for_each(|high_block| {
            high_block.into_iter().for_each(|mid_block| {
                mid_block.1.into_iter().for_each(|each_value| {
                    let _ = statement.bind(&[(":key", mid_block.0.as_str()), (":value", each_value.as_str())][..]);
                    while let Ok(State::Row) = statement.next() {}
                    let _ = statement.reset();
                });
            });
        });
    }

    fn compare_key_xvalues(&self, connx: Arc<ConnectionWithFullMutex>, yara_checker: Option<Arc<Rules>>, entries: Vec<Vec<(String, Vec<String>)>>, table_to_select: String) {
        let query = format!("SELECT * FROM {} WHERE key=:key", table_to_select);
        let mut stmt = connx.prepare(query).unwrap();
        let mut buf_writer = match self.create_bufwriter() {
            Ok(x) => x,
            Err(err) => panic!("{}", err),
        };
        let _ = buf_writer.write_all("file_name;setting_name;setting_config;yara_match;yara_rulename\n".as_bytes());
        entries.into_iter().for_each(|high_block| {
            high_block.into_iter().for_each(|mid_block| {
                let mut ref_values: Vec<String> = vec![];
                let _ = stmt.bind((":key", mid_block.0.as_str()));
                while let Ok(State::Row) = stmt.next() {
                    let a_value: String = stmt.read(1).unwrap();
                    ref_values.push(a_value);
                }
                let _ = stmt.reset();
                mid_block.1.into_iter().for_each(|each_value| {
                    if !ref_values.contains(&each_value) {
                        let mut matched_rules_names = String::new();
                        let mut flag: bool = false;
                        if let Some(yara_checker) = &yara_checker {
                            if let Ok(yara_matches) = yara_checker.scan_mem(format!("{} {}", mid_block.0, each_value).as_bytes(), 5){
                                if !yara_matches.is_empty() {
                                    if !flag { flag = true; }
                                    yara_matches.into_iter().for_each(|x| {
                                        matched_rules_names.push_str(format!("[{}]", x.identifier).as_str());
                                    });
                                }
                            };
                        };
                        if flag {
                            let _ = buf_writer.write_all(format!("{};{};{};true;{}\n", self.path_filename.as_str(), mid_block.0, each_value, matched_rules_names.as_str()).as_bytes());
                        }
                        else {
                            let _ = buf_writer.write_all(format!("{};{};{};false;\n", self.path_filename.as_str(), mid_block.0, each_value).as_bytes());
                        }
                    }
                });
            });
        });
    }

    fn create_key_3values_table_ref(&self, connx: Arc<ConnectionWithFullMutex>, table_to_create: String, entries: Vec<(String, String, String, String)>, headers: (String, String, String, String)) {
        let query_table = format!("CREATE TABLE '{table_to_create}' ({} TEXT, {} TEXT, {} TEXT, {} TEXT)", headers.0, headers.1, headers.2, headers.3);
        let _ = connx.execute(query_table);
        let query_insert = format!("INSERT INTO '{table_to_create}' ({}, {}, {}, {}) VALUES (:key, :val1, :val2, :val3)", headers.0, headers.1, headers.2, headers.3);
        let mut statement = connx.prepare(query_insert).unwrap();
        entries.into_iter().for_each(|a_volume| {
            let _ = statement.bind(&[(":key", a_volume.0.as_str()),
                    (":val1", a_volume.1.as_str()),
                    (":val2", a_volume.2.as_str()),
                    (":val3", a_volume.3.as_str())]
                    [..]
            );
            while let Ok(State::Row) = statement.next() {}
            let _ = statement.reset();
        });
    }

    fn compare_key_3values(&self, connx: Arc<ConnectionWithFullMutex>, yara_checker: Option<Arc<Rules>>, table_to_select: String, entries: Vec<(String, String, String, String)>, header: String) {
        let query = format!("SELECT * FROM '{}' WHERE {}=:key", table_to_select, header);
        let mut stmt = connx.prepare(query).unwrap();
        let mut buf_writer = match self.create_bufwriter() {
            Ok(x) => x,
            Err(err) => panic!("{}", err),
        };
        let _ = buf_writer.write_all(format!("file_name;{};{};{};{};yara_match;yara_rulename\n"
                , stmt.column_name(0).unwrap_or("setting_name")
                , stmt.column_name(1).unwrap_or("setting_config1")
                , stmt.column_name(2).unwrap_or("setting_config2")
                , stmt.column_name(3).unwrap_or("setting_config3")).as_bytes());
        entries.into_iter().for_each(|each_entry| {
            let mut flag: bool = false;
            let _ = stmt.bind((":key", each_entry.0.as_str()));
            while let Ok(State::Row) = stmt.next() {
                let values: (String, String, String) = (stmt.read(1).unwrap(), stmt.read(2).unwrap(), stmt.read(3).unwrap());
                // println!("Compare {},{},{} -> {}, {}, {}", each_entry.1, each_entry.2, each_entry.3, values.0, values.1, values.2);
                if each_entry.1 == values.0 && each_entry.2 == values.1 && each_entry.3 == values.2 {
                    flag = true;
                }
            }
            if !flag {
                let mut matched_rules_names = String::new();
                flag = false;
                if let Some(yara_checker) = &yara_checker {
                    if let Ok(yara_matches) = yara_checker.scan_mem(format!("{} {} {} {}", each_entry.0, each_entry.1, each_entry.2, each_entry.3).as_bytes(), 5){
                        if !yara_matches.is_empty() {
                            if !flag { flag = true; }
                            yara_matches.into_iter().for_each(|x| {
                                matched_rules_names.push_str(format!("[{}]", x.identifier).as_str());
                            });
                        }
                    };
                };
                if flag {
                    let _ = buf_writer.write_all(format!("{};{};{};{};{};true;{}\n", self.path_filename.as_str(), each_entry.0, each_entry.1, each_entry.2, each_entry.3, matched_rules_names.as_str()).as_bytes());
                }
                else {
                    let _ = buf_writer.write_all(format!("{};{};{};{};{};;\n", self.path_filename.as_str(), each_entry.0, each_entry.1, each_entry.2, each_entry.3).as_bytes());
                }
            }
            let _ = stmt.reset();
        });
    }

    fn create_5values_block_table_ref(&self, connx: Arc<ConnectionWithFullMutex>, table_to_create: String, entries: Vec<[String; 5]>, headers: (String, String, String, String, String)) {
        let query_table = format!("CREATE TABLE '{table_to_create}' ({} TEXT, {} TEXT, {} TEXT, {} TEXT, {} TEXT)", headers.0, headers.1, headers.2, headers.3, headers.4);
        let _ = connx.execute(query_table);
        let query_insert = format!("INSERT INTO '{table_to_create}' ({0}, {1}, {2}, {3}, {4}) VALUES (:{0}, :{1}, :{2}, :{3}, :{4})", headers.0, headers.1, headers.2, headers.3, headers.4);
        let mut statement = connx.prepare(query_insert).unwrap();
        entries.into_iter().for_each(|block| {
            // blocks -> permission, package, label, description, protectionLevel
            let _ = statement.bind_iter([
                (format!(":{}", headers.0).as_str(), block[0].as_str()),
                (format!(":{}", headers.1).as_str(), block[1].as_str()),
                (format!(":{}", headers.2).as_str(), block[2].as_str()),
                (format!(":{}", headers.3).as_str(), block[3].as_str()),
                (format!(":{}", headers.4).as_str(), block[4].as_str()),
            ]);
            while let Ok(State::Row) = statement.next() {}
            let _ = statement.reset();
        });
    }

    fn compare_5values_block(&self, connx: Arc<ConnectionWithFullMutex>, yara_checker: Option<Arc<Rules>>, entries: Vec<[String; 5]>, table_to_select: String, header: String) {
        let query = format!("SELECT * FROM '{}' WHERE {}=:key", table_to_select, header);
        let mut stmt = connx.prepare(query).unwrap();
        let mut buf_writer = match self.create_bufwriter() {
            Ok(x) => x,
            Err(err) => panic!("{}", err),
        };
        let _ = buf_writer.write_all(format!("file_name;{};{};{};{};{};yara_match;yara_rulename\n"
                , stmt.column_name(0).unwrap_or("setting_config1")
                , stmt.column_name(1).unwrap_or("setting_config2")
                , stmt.column_name(2).unwrap_or("setting_config3")
                , stmt.column_name(3).unwrap_or("setting_config4")
                , stmt.column_name(4).unwrap_or("setting_config5")).as_bytes());
        entries.into_iter().for_each(|blocks| {
            // Array : permission, package, label, description, protectionLevel
            let mut flag: bool = false;
            let _ = stmt.bind((":key", blocks[0].as_str()));
            while let Ok(State::Row) = stmt.next() {
                let values: (String, String, String, String) = (stmt.read(1).unwrap(), stmt.read(2).unwrap(), stmt.read(3).unwrap(), stmt.read(4).unwrap());
                if values.0 == blocks[1] && values.1 == blocks[2] && values.2 == blocks[3] && values.3 == blocks[4] {
                    flag = true;
                }
            }
            if !flag {
                let mut matched_rules_names = String::new();
                flag = false;
                if let Some(yara_checker) = &yara_checker {
                    if let Ok(yara_matches) = yara_checker.scan_mem(format!("{} {} {} {} {}", blocks[0], blocks[1], blocks[2], blocks[3], blocks[4]).as_bytes(), 5){
                        if !yara_matches.is_empty() {
                            if !flag { flag = true; }
                            yara_matches.into_iter().for_each(|x| {
                                matched_rules_names.push_str(format!("[{}]", x.identifier).as_str());
                            });
                        }
                    };
                };
                if flag {
                    let _ = buf_writer.write_all(format!("{};{};{};{};{};{};true;{}\n", self.path_filename.as_str(), blocks[0], blocks[1], blocks[2], blocks[3], blocks[4], matched_rules_names.as_str()).as_bytes());
                }
                else {
                    let _ = buf_writer.write_all(format!("{};{};{};{};{};{};;\n", self.path_filename.as_str(), blocks[0], blocks[1], blocks[2], blocks[3], blocks[4]).as_bytes());
                }
            }
            let _ = stmt.reset();
        });
    }

    fn parse_getprop(&self, read_buffer: io::BufReader<fs::File>) -> Vec<(String, String)> {
        let mut results: Vec<(String, String)> = vec![];
        let re = match Regex::new(r"^\[(?P<part1>.*)\]: \[(?P<part2>.*)\]$") {
            Ok(x) => x,
            Err(err) => panic!("{}", err),
        };
        for line in read_buffer.lines() {
            let line_str = match line {
                Ok(x) => x,
                Err(_err) => String::from(""),
            };
            let catches: (String, String) = match re.captures(line_str.as_str()) {
                Some(caps) => (caps.name("part1").map_or("".to_string(), |m| String::from(m.as_str())),
                                            caps.name("part2").map_or("".to_string(), |m| String::from(m.as_str()))),
                None => { continue; },
            };
            results.push(catches);
        }
        results
    }
    
    fn parse_settings(&self, read_buffer: io::BufReader<fs::File>) -> Vec<(String, String)> {
        let mut results = vec![];
        for line in read_buffer.lines() {
            let line_str = match line {
                Ok(x) => x,
                Err(_err) => { continue; },
            };
            let mut splited_str = line_str.split("=");
            let val1: &str = match splited_str.next() {
                Some(x) => x,
                None => "",
            };
            let val2: &str = match splited_str.next() {
                Some(x) => x,
                None => "",
            };
            results.push((val1.to_string(), val2.to_string()));
        }
        results
    }
    
    fn parse_df_ah(&self, read_buffer: io::BufReader<fs::File>) -> Vec<(String, String)>{
        let mut results: Vec<(String, String)> = vec![];
        for line in read_buffer.lines() {
            let line_str = match line {
                Ok(x) => x,
                Err(_err) => { continue; },
            };
            let splited_str: Vec<&str> = line_str.split_whitespace().into_iter().collect();
            if splited_str.len() == 6 {
                let first = splited_str.first().unwrap();
                let last = splited_str.last().unwrap();
                results.push((first.to_string(), last.to_string()));
            }
        }
        results
    }
    
    fn parse_id(&self, read_buffer: io::BufReader<fs::File>) -> Vec<Vec<(String, Vec<String>)>> {
        let mut results: Vec<Vec<(String, Vec<String>)>> = vec![];
        for line in read_buffer.lines() {
            let line_str = match line {
                Ok(x) => x,
                Err(_err) => String::from(""),
            };
            let splited_str = line_str.split_whitespace();
            splited_str.into_iter().for_each(|each_split| {
                let coupled_values: Vec<String> = each_split.split("=").map(|x| x.to_string()).collect();
                let mut temp_vec: Vec<(String, Vec<String>)> = vec![];
                let group_name = match coupled_values.first() {
                    Some(x) => x,
                    None => "",
                };
                let gathered_users: Vec<String> = match coupled_values.last() {
                    Some(x) => x.to_string().split(",").map(|x| x.to_string()).collect(),
                    None => vec![],
                };
                temp_vec.push((group_name.to_string(), gathered_users));
                results.push(temp_vec);
            });
        }
        results
    }
    
    fn parse_mount(&self, read_buffer: io::BufReader<fs::File>) -> Vec<(String, String, String, String)> {
        let mut results: Vec<(String, String, String, String)> = vec![];
        for line in read_buffer.lines() {
            let line_str = match line {
                Ok(x) => x,
                Err(_err) => String::from(""),
            };

            let re =  match Regex::new(r"^(?P<NAME>\S+)\s+on\s+(?P<MOUNTPOINT>.+)\s+type\s+(?P<TYPE>\S+)\s+\((?P<OPTIONS>\S+)\)$") {
                Ok(x) => x,
                Err(err) => panic!("{}", err),
            };
            let caps = re.captures(line_str.as_str());
            let values: (String, String, String, String) = match caps {
                Some(caps) => (caps.name("NAME").map_or("".to_string(), |m| m.as_str().to_string()),
                    caps.name("MOUNTPOINT").map_or("".to_string(), |m| m.as_str().to_string()),
                    caps.name("TYPE").map_or("".to_string(), |m| m.as_str().to_string()),
                    caps.name("OPTIONS").map_or("".to_string(), |m| m.as_str().to_string())),
                None => { continue; },
            };
            results.push(values);
        }
        results
    }
    
    fn parse_ps(&self, read_buffer: io::BufReader<fs::File>) -> Vec<(String, String, String, String)> {
        let mut results: Vec<(String, String, String, String)> = vec![];
        for line in read_buffer.lines() {
            let line_str = match line {
                Ok(x) => x,
                Err(_err) => String::from(""),
            };
            let re =  match Regex::new(r"^(?P<UID>\w+)\s+(?P<PID>\d+)\s+(?P<PPID>\d+)(\s+\S+){4}\s+(?P<CMD>\[?\w+(\/\d+(:\d+)?)?\]?)$") {
                Ok(x) => x,
                Err(err) => panic!("{}", err),
            };
            let caps = re.captures(line_str.as_str());
            let values: (String, String, String, String) = match caps {
                                                        Some(caps) => (caps.name("UID").map_or("".to_string(), |m| m.as_str().to_string()),
                                                            caps.name("PID").map_or("".to_string(), |m| m.as_str().to_string()),
                                                            caps.name("PPID").map_or("".to_string(), |m| m.as_str().to_string()),
                                                            caps.name("CMD").map_or("".to_string(), |m| m.as_str().to_string())),
                                                        None => { continue; },
            };
            results.push(values);
        }
        results
    }
    
    fn parse_services(&self, read_buffer: io::BufReader<fs::File>) -> Vec<(String, String)> {
        let mut results: Vec<(String, String)> = vec![];
        for line in read_buffer.lines() {
            let line_str = match line {
                Ok(x) => x,
                Err(_err) => String::from(""),
            };
            let re = match Regex::new(r"^\d+\s+(?P<SVCNAME>\S+): (?P<SVCVAL>\S+)$") {
                Ok(x) => x,
                Err(err) => panic!("{}", err),
            };
            let caps = re.captures(line_str.as_str());
            let values: (&str, &str) = match caps {
                                    Some(caps) => (caps.name("SVCNAME").map_or("", |m| m.as_str()),
                                                                caps.name("SVCVAL").map_or("", |m| m.as_str())),
                                    None => { continue; },
            };
            results.push((values.0.to_string(), values.1.to_string()));
        }
        results
    }
    
    fn parse_list(&self, read_buffer: io::BufReader<fs::File>) -> Vec<(String, String)> {
        let mut results: Vec<(String, String)> = vec![];
        for line in read_buffer.lines() {
            let line_str = match line {
                Ok(x) => x,
                Err(_err) => String::from(""),
            };
            let splitted_str: Vec<String> = line_str.split(":").map(|x| x.to_string()).collect();
            results.push((splitted_str.first().unwrap().to_string(), splitted_str.last().unwrap().to_string()));
        }
        results
    }
    
    fn parse_permissions_list(&self, read_buffer: io::BufReader<fs::File>) -> Vec<[String; 5]> {
        let mut results: Vec<[String; 5]> = vec![];
        let mut block_counter: usize = 0;
        let mut row_values: [String; 5] = Default::default();
        for line in read_buffer.lines() {
            let line_str = match line {
                Ok(x) if x.starts_with("+ ") | x.starts_with("  ") => String::from(&x[2..]),
                Ok(_) | Err(_) => continue,
            };
            let splitted_line: Vec<String> = line_str.split(":").map(|x| x.to_string()).collect();
            row_values[block_counter] = splitted_line.last().unwrap().to_string();
            if block_counter >= 4 {
                results.push(row_values);
                block_counter = 0;
                row_values = Default::default();
            }
            else {
                block_counter += 1;
            }
        }
        results
    }

    fn android_file_selector(&self, buf_reader: io::BufReader<fs::File>, connx: Arc<ConnectionWithFullMutex>, yara_checker: Option<Arc<Rules>>) {
        let path_filename = path::Path::new(&self.path_filename);
        match path_filename.file_name() {
            Some(x) => {
                let mut splited_str = x.to_str().unwrap().split(".");
                let parted = splited_str.next().unwrap();
                if parted == "getprop"  {
                    self.compare_key_value(connx, yara_checker, self.parse_getprop(buf_reader), parted.to_string());
                }
                else if parted.starts_with("settings_") || parted.starts_with("printenv.txt") {
                    self.compare_key_value(connx, yara_checker, self.parse_settings(buf_reader), parted.to_string());
                }
                else if parted == "df_ah" {
                    self.compare_key_value(connx, yara_checker, self.parse_df_ah(buf_reader), parted.to_string());
                }
                else if parted == "services" {
                    self.compare_key_value(connx, yara_checker, self.parse_services(buf_reader), parted.to_string());
                }
                else if parted == "id" {
                    self.compare_key_xvalues(connx, yara_checker, self.parse_id(buf_reader), parted.to_string());
                }
                else if parted == "mount" {
                    self.compare_key_3values(connx, yara_checker, parted.to_string(), self.parse_mount(buf_reader), "name".to_string());
                }
                else if parted == "ps" {
                    self.compare_key_3values(connx, yara_checker, parted.to_string(), self.parse_ps(buf_reader), "uid".to_string());
                }
                else if parted == "pm_list_permissions-f" {
                    self.compare_5values_block(connx, yara_checker, self.parse_permissions_list(buf_reader), parted.to_string(), "permission".to_string());
                }
                else if parted.starts_with("pm_list_") & !parted.ends_with("users") {   //TODO pm_list_permissions-f AVANT Celui lui.
                    self.compare_key_value(connx, yara_checker, self.parse_list(buf_reader), parted.to_string());
                }

            },
            _ => (),
        };
    }

    fn android_file_reference(&self, buf_reader: io::BufReader<fs::File>, connx: Arc<ConnectionWithFullMutex>) {
        let path_filename = path::Path::new(&self.path_filename);
        match path_filename.file_name() {
            Some(x) => { 
                let mut splited_str = x.to_str().unwrap().split(".");
                let parted = splited_str.next().unwrap();
                if x == "getprop.txt" {
                    self.create_key_value_table_ref(connx
                            , parted.to_string()
                            , self.parse_getprop(buf_reader)
                    );
                }
                else if parted.starts_with("settings_") || parted == "printenv" {
                    self.create_key_value_table_ref(connx
                            ,parted.to_string()
                            , self.parse_settings(buf_reader)
                    );
                }
                else if parted.starts_with("df_ah") {
                    self.create_key_value_table_ref(connx
                            ,parted.to_string()
                            , self.parse_df_ah(buf_reader)
                    );
                }
                else if parted == "id" {
                    self.create_key_xvalues_table_ref(connx
                            , parted.to_string()
                            , self.parse_id(buf_reader)
                    );
                }
                else if parted == "mount" {
                    let headers: (String, String, String, String) = ("name".to_string(), "mountpoint".to_string(), "type".to_string(), "options".to_string());
                    self.create_key_3values_table_ref(connx
                            ,parted.to_string()
                            , self.parse_mount(buf_reader)
                            , headers
                    );
                }
                else if parted == "ps" {
                    let headers: (String, String, String, String) = ("uid".to_string(), "pid".to_string(), "ppid".to_string(), "cmd".to_string());
                    self.create_key_3values_table_ref(connx
                            , parted.to_string()
                            , self.parse_ps(buf_reader)
                            , headers
                    );
                }
                else if parted == "services" {
                    self.create_key_value_table_ref(connx
                            ,parted.to_string()
                            , self.parse_services(buf_reader)
                    );
                }
                else if parted == "pm_list_permissions-f" {
                    let headers: (String, String, String, String, String) = ("permission".to_string(), "package".to_string(), "label".to_string(), "description".to_string(), "protectionlevel".to_string());
                    self.create_5values_block_table_ref(connx
                            ,parted.to_string()
                            , self.parse_permissions_list(buf_reader)
                            , headers
                        );
                }
                else if parted.starts_with("pm_list_") & !parted.ends_with("users") {
                    self.create_key_value_table_ref(connx
                            ,parted.to_string()
                            , self.parse_list(buf_reader)
                    );
                }
            },
            // Some(x) if x.to_str().unwrap().starts_with("pm_list_") & !x.to_str().unwrap().ends_with("users.txt") => self.parse_list(buf_reader),
            _ => (),
        };
    }
}
