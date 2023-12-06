//! AndroidParser
//! 
//! AndroidParser is a a crate getting a path filename and
//! is able to run a referencing to a volatile DB or
//! comparing against this DB.

use std::{io::{Cursor, BufRead, BufReader, BufWriter, Error, ErrorKind, Write}, fs::{File, OpenOptions}, path::Path, sync::{Arc, Mutex}, env::current_dir};
use regex::Regex;
use sqlite::{ConnectionThreadSafe, State};
use yara::{Rules, Scanner};
use sha256;

pub struct AndroidParser {
    path_analyze: String,
    path_reference: String,
    yara_report_file_mutexed: Arc<Mutex<BufWriter<File>>>,
    yara_rules: Vec<Rules>,
    connx: Arc<ConnectionThreadSafe>
}

impl AndroidParser {
    /// Create a new AndroidParser. Taking a file path, verifying it and returning a valid AndroidParser.
    /// 
    /// # Exemple
    /// 
    /// ```
    /// let file_path = path.Path::new("C:/Smartphones/S21/infos/getprops.txt");
    /// 
    /// let android_parser = AndroidParser::new(file_path);
    pub fn new(path_reference: String,
            path_analyze: String,
            path_yara: Option<String>) -> Result<Self, Error>
    {
        match Path::new(&path_reference).try_exists().unwrap() & Path::new(&path_analyze).try_exists().unwrap() {
            true => {
                let yara_default_rules = Rules::load_from_stream(
                        Cursor::new(
                        include_bytes!("../../resources/yara_precompiled.yara")
                )
                ).unwrap();
                let mut yara_rules: Vec<Rules> = vec![yara_default_rules];
                if let Some(yara_path) = path_yara {
                    yara_rules.push(yara_customizer::yara_rules_ingester(yara_customizer::yara_rules_finder(Path::new(&yara_path))));
                }

                let connx: Arc<ConnectionThreadSafe> = match sqlite::Connection::open_thread_safe(":memory:") {
                    Ok(x) => Arc::new(x),
                    Err(err) => panic!("{err}"),
                };
                
                let yara_report_file_mutexed: Arc<Mutex<BufWriter<File>>> = match OpenOptions::new()
                        .read(true)
                        .write(true)
                        .append(true)
                        .create(true)
                        .open(Path::new(format!("{}/reported_yara_matches.csv",
                                current_dir().unwrap().to_str().unwrap()).as_str())
                        )
                {
                    Ok(file_handler) => Arc::new(Mutex::new(BufWriter::new(file_handler))),
                    Err(err) => panic!("{}", err.to_string()),
                };
                return Ok(Self {path_reference, path_analyze, yara_report_file_mutexed, yara_rules, connx})
            },
            false => return Err(Error::new(
                    ErrorKind::NotFound,
                    "File not Found")
            ),
        };
    }

    /// Using the 'self.path_filename', this method will select a parser to
    /// find the way to extract parameters and compare it with the given Sqlite DB 'connx'.
    /// if it is not as the Ref, will use the given Yara scanner vector 'yara_checker'
    /// to check if there is malicious entries.
    /// 
    /// # Exemple
    /// 
    /// ```
    /// let connection = match sqlite::Connection::open_thread_safe(":memory:") {
    ///     Ok(x) => Arc::new(x),
    ///     Err(err) => panic!("{err}"),
    /// };
    /// 
    /// let yara_rules = Rules::load_from_stream(Cursor::new(include_bytes!("../resources/yara_precompiled.yara"))).unwrap();
    /// let yara_scanners = vec![yara_rules.scanner().unwrap()];
    /// 
    /// android_parser.go_parse(connection.clone(), yara_scanners);
    pub fn go_parse(&self) {
        self.parse_path(self.path_analyze.clone());
    }

    /// Using 'self.path_filename', and the 'connx' given, will parse the file to extract datas from concerned
    /// file, and organize them into de DB 'connx'.
    /// 
    /// # Exemples
    /// 
    /// ```
    /// let connection = match sqlite::Connection::open_thread_safe(":memory:") {
    ///     Ok(x) => Arc::new(x),
    ///     Err(err) => panic!("{err}"),
    /// };
    /// let android_parser = match AndroidParser::new(path.Path::new("C:/Smartphones/S21/infos/getprops.txt")) {
    ///     Ok(x) => {
    ///         x.go_ref(connection);
    ///     },
    ///     Err(err) => eprintln!("{err}"),
    /// };
    pub fn go_ref(&self) {
        self.parse_ref(self.path_reference.clone());
    }

    fn create_bufreader(&self,
            path: &Path) -> Result<BufReader<File>, Error>
    {
        let file_handler = OpenOptions::new()
                .read(true)
                .write(false)
                .create(false)
                .open(path)
        ;
        match file_handler {
            Ok(x) => return Ok(BufReader::new(x)),
            Err(err) => return Err(err),
        };
    }

    fn create_bufwriter(&self, 
            path: &str) -> Result<BufWriter<File>, Error>
    {
        let re = match regex::Regex::new(r"^(?P<REPORTPATH>\w:\\.*\\).*\\(?P<REPORTNAME>.*)\.txt$") {
            Ok(x) => x,
            Err(err) => panic!("{}", err),
        };
        if let Some(caps) = re.captures(path) {
            let report_filename = format!("{}{}.csv",
                    caps.name("REPORTPATH").map_or("".to_string(), |m| String::from(m.as_str())),
                    caps.name("REPORTNAME").map_or("".to_string(), |m| String::from(m.as_str()))
            );
            let file = match OpenOptions::new()
                    .read(true)
                    .write(true)
                    .append(true)
                    .create(true)
                    .open(Path::new(report_filename.as_str()))
            {
                Ok(x) => x,
                Err(err) => panic!("{}", err),
            };
            return Ok(BufWriter::new(file))
        }
        else if let Some(caps) = Regex::new(r"^(?P<REPORTPATH>\w:[\\/].*[\\/])system[\\/]bin[\\/](?P<REPORTNAME>.*)$").unwrap()
                .captures(path)
        {
            let report_filename = format!("{}{}",
                    caps.name("REPORTPATH").map_or("".to_string(), |m| String::from(m.as_str())),
                    String::from("binaries.csv")
            );
            let file = match OpenOptions::new()
                    .read(true)
                    .write(true)
                    .append(true)
                    .create(true)
                    .open(Path::new(report_filename.as_str()))
            {
                Ok(x) => x,
                Err(err) => panic!("{err}"),
            };
            return Ok(BufWriter::new(file))
        }
        else {
            return Err(Error::new(ErrorKind::InvalidData,
                    "Error occured while creating the File buffer to write report")
            )
        }
    }

    fn parse_path(&self,
            path: String
    ) {
        let path = Path::new(path.as_str());
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
                                self.parse_path(String::from(each_entry.path().to_str().unwrap())); 
                            }
                            else if each_entry.file_type().unwrap().is_file() &&
                                    ( each_entry.path().extension().is_some_and(|x| x.to_str().unwrap() == "txt") ||
                                    Regex::new(r"[\\/]system[\\/]bin[\\/].*$").unwrap().is_match(each_entry.path().to_str().unwrap()) )
                            {
                                let mut vec_yara_scanner: Vec<Scanner> = vec![];
                                self.yara_rules.iter().for_each(|yara_rules| {
                                    let mut yara_scanner = yara_rules.scanner().unwrap();
                                    yara_scanner.set_timeout(10);
                                    yara_scanner.set_flags(yara::ScanFlags::REPORT_RULES_MATCHING);
                                    vec_yara_scanner.push(yara_scanner);
                                });
                                s.spawn(move |_| {
                                    let _ = match self.create_bufreader(each_entry.path().as_path()) {
                                        Ok(x) => self.android_file_selector(x,
                                            String::from(each_entry.path().to_str().unwrap())
                                        ),
                                        Err(err) => panic!("{err}")
                                    };

                                });
                            }
                            else {
                                if let Ok(Some(_)) = infer::get_from_path(each_entry.path().to_str().unwrap()) {
                                    let mut vec_yara_scanner: Vec<Scanner> = vec![];
                                    let mut matched_rules: (String, String, String) = (String::new(), String::new(), String::new());
                                    self.yara_rules.iter().for_each(|yara_rules| {
                                        let mut yara_scanner = yara_rules.scanner().unwrap();
                                        yara_scanner.set_timeout(10);
                                        yara_scanner.set_flags(yara::ScanFlags::REPORT_RULES_MATCHING);
                                        vec_yara_scanner.push(yara_scanner);
                                    });
                                    let local_yara_report_file_mutexed = self.yara_report_file_mutexed.clone();
                                    s.spawn( move |_| {
                                        vec_yara_scanner.iter_mut().for_each(|yara_scanner| {
                                            if let Ok(yara_matches) = yara_scanner.scan_file(each_entry.path()){
                                                if !yara_matches.is_empty() {
                                                    yara_matches.into_iter().for_each(|x| {
                                                        if !matched_rules.0.contains(x.identifier) {
                                                            if !( x.identifier.eq("with_sqlite") & each_entry.path().extension().is_some_and(|x| x.to_str().unwrap() == "db") ) &
                                                                    !( (x.identifier.eq("ft_jar") | x.identifier.eq("ft_zip")) & each_entry.path().extension().is_some_and(|x| x.to_str().unwrap() == "apk") ) &
                                                                    !( x.identifier.eq("ft_zip") & each_entry.path().extension().is_some_and(|x| x.to_str().unwrap() == "zip") ) &
                                                                    !( x.identifier.eq("ft_gzip") & each_entry.path().extension().is_some_and(|x| x.to_str().unwrap() == "gz") ) & 
                                                                    !( (x.identifier.eq("ft_elf") | x.identifier.eq("executable_elf32") | x.identifier.eq("executable_elf64")) & Regex::new(r"[\\/]system[\\/]bin.*$").unwrap().is_match(each_entry.path().to_str().unwrap()) ) {
                                                                let mut tmp_desc = String::new();
                                                                let mut tmp_ref = String::new();
                                                                x.metadatas.iter().for_each(|y| {
                                                                    if y.identifier.contains("desc") || 
                                                                            y.identifier.contains("description")
                                                                    {
                                                                        let str = format!("{:?}", y.value);
                                                                        tmp_desc.push_str(&format!("[{}]", &str[8..str.len()-2]));
                                                                    }
                                                                    if y.identifier.eq("url") ||
                                                                            y.identifier.eq("reference")
                                                                    {
                                                                        let str = format!("{:?}", y.value);
                                                                        tmp_ref.push_str(&format!("[{}]", &str[8..str.len()-2]));
                                                                    }
                                                                });
                                                                if tmp_desc.is_empty() {
                                                                    matched_rules.1.push_str("[---]");
                                                                }
                                                                else {
                                                                    matched_rules.1.push_str(&tmp_desc);
                                                                }
                                                                if tmp_ref.is_empty() {
                                                                    matched_rules.2.push_str("[---]");
                                                                }
                                                                else {
                                                                    matched_rules.2.push_str(&tmp_ref);
                                                                }
                                                                matched_rules.0.push_str(format!("[{}]", x.identifier).as_str());
                                                            }
                                                        }
                                                    });
                                                }
                                            };
                                        });
                                        if !matched_rules.0.is_empty() {
                                            let mut garded_writer = local_yara_report_file_mutexed.lock().unwrap();
                                            let _ = garded_writer.write_all(format!("{};{};{};{}\n",
                                                    each_entry.path().to_str().unwrap(),
                                                    matched_rules.0,
                                                    matched_rules.1,
                                                    matched_rules.2
                                                ).as_bytes()
                                            );
                                        }
                                    });
                                }
                            }
                        }
                    });
                });
            }
        }
    }

fn parse_ref(&self,
        path: String)
{
    let path = Path::new(path.as_str());
    let validator_flag = match path.try_exists() {
        Ok(x)=> x,
        Err(err) => panic!("[Error] {}", err.to_string()),
    };
    if validator_flag && path.is_dir() {
        if let Ok(read_dir) = path.read_dir() {
            rayon::scope(|s| {
                for each_dir in read_dir {
                    if let Ok(each_entry) = each_dir {
                        if each_entry.file_type().unwrap().is_dir() {
                            self.parse_ref(String::from(each_entry.path().to_str().unwrap()))
                        }
                        else if each_entry.file_type().unwrap().is_file() &&
                                ( each_entry.path().extension().is_some_and(|x| x.to_str().unwrap() == "txt") ||
                                Regex::new(r"[\\/]system[\\/]bin[\\/].*$").unwrap().is_match(each_entry.path().to_str().unwrap()) )
                        {
                            s.spawn(move |_| {
                                let _ = match self.create_bufreader(each_entry.path().as_path()){
                                    Ok(buf_reader) => self.android_file_reference(String::from(each_entry.path().to_str().unwrap()),
                                            buf_reader),
                                    Err(err) => println!("[Error] {}", err),
                                };
                            });
                        }
                    }
                }
            });
        }
    }
}

    fn create_key_value_table_ref(&self,
            table_to_create: String,
            entries: Vec<(String, String)>
    ){
        let query_table = format!("CREATE TABLE '{}' (key TEXT, value TEXT)",
                table_to_create
        );
        let _ = self.connx.execute(query_table);
        let query_insert = format!("INSERT INTO '{}' (key, value) VALUES (:key, :value)",
                table_to_create
        );
        let mut statement = self.connx.prepare(query_insert).unwrap();
        entries.iter().for_each(|couple| {
            let _ = statement.bind(&[
                (":key", couple.0.as_str()),
                (":value", couple.1.as_str()),
            ][..]);
            while let Ok(State::Row) = statement.next() {}
            let _ = statement.reset();
        });
    }

    fn compare_key_value(&self,
            file_path: String,
            entries: Vec<(String, String)>,
            table_to_select: String
    ){
        let query = format!("SELECT * FROM '{}' WHERE key=:key",
                table_to_select);
        let mut stmt = self.connx.prepare(query.as_str()).unwrap();
        let mut buf_writer = match self.create_bufwriter(&file_path) {
            Ok(x) => x,
            Err(err) => panic!("{}", err),
        };
        let _ = buf_writer.write_all("file_name;setting_name;setting_config;yara_match;yara_rulename\n".as_bytes());
        entries.into_iter().for_each(|each_entry| {
            let _ = stmt.bind((":key",
                    each_entry.0.as_str())
            );
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
                let mut yara_checker: Vec<Scanner> = vec![];
                self.yara_rules.iter().for_each(|a_rule| yara_checker.push(a_rule.scanner().unwrap()));
                yara_checker.iter_mut().for_each(|yara_scanner| {
                    if let Ok(yara_matches) = yara_scanner.scan_mem(format!("{} {}",
                                each_entry.0,
                                each_entry.1
                            )
                            .as_bytes()
                    ){
                        if !yara_matches.is_empty() {
                            if !flag { flag = true; }
                            yara_matches.into_iter().for_each(|x| {
                                // println!("[REPORT] Yara matched => {}\n=>\t{}", x.identifier, self.path_filename);
                                if !matched_rules_names.contains(format!("[{}]",
                                        x.identifier).as_str()
                                ){
                                    matched_rules_names.push_str(format!("[{}]",
                                                x.identifier
                                            )
                                        .as_str()
                                    );
                                }
                            });
                        }
                    };
                });
                if flag {
                    let _ = buf_writer.write_all(format!("{};{};{};true;{}\n",
                                file_path.as_str(),
                                each_entry.0,
                                each_entry.1,
                                matched_rules_names.as_str()
                            )
                            .as_bytes()
                    );
                }
                else {
                    let _ = buf_writer.write_all(format!("{};{};{};false;\n",
                                file_path.as_str(),
                                each_entry.0,
                                each_entry.1
                            )
                            .as_bytes()
                    );
                }
            }
        })
    }
    
    fn create_key_xvalues_table_ref(&self,
            table_to_create: String,
            entries: Vec<Vec<(String, Vec<String>)>>
    ){
        let query_table = format!("CREATE TABLE '{}' (key TEXT, value TEXT)",
                table_to_create);
        let _ = self.connx.execute(query_table);
        let query_insert = format!("INSERT INTO '{}' (key, value) VALUES (:key, :value)",
                table_to_create);
        let mut statement = self.connx.prepare(query_insert).unwrap();
        entries.into_iter().for_each(|high_block| {
            high_block.into_iter().for_each(|mid_block| {
                mid_block.1.into_iter().for_each(|each_value| {
                    let _ = statement.bind(&[(":key", mid_block.0.as_str()),
                            (":value", each_value.as_str())]
                            [..]
                    );
                    while let Ok(State::Row) = statement.next() {}
                    let _ = statement.reset();
                });
            });
        });
    }

    fn compare_key_xvalues(&self,
            file_path: String,
            entries: Vec<Vec<(String, Vec<String>)>>, 
            table_to_select: String
    ){
        let query = format!("SELECT * FROM {} WHERE key=:key",
                table_to_select
        );
        let mut stmt = self.connx.prepare(query).unwrap();
        let mut buf_writer = match self.create_bufwriter(&file_path) {
            Ok(x) => x,
            Err(err) => panic!("{}", err),
        };
        let _ = buf_writer.write_all("file_name;setting_name;setting_config;yara_match;yara_rulename\n".as_bytes());
        entries.into_iter().for_each(|high_block| {
            high_block.into_iter().for_each(|mid_block| {
                let mut ref_values: Vec<String> = vec![];
                let _ = stmt.bind((":key",
                        mid_block.0.as_str())
                );
                while let Ok(State::Row) = stmt.next() {
                    let a_value: String = stmt.read(1).unwrap();
                    ref_values.push(a_value);
                }
                let _ = stmt.reset();
                mid_block.1.into_iter().for_each(|each_value| {
                    if !ref_values.contains(&each_value) {
                        let mut matched_rules_names = String::new();
                        let mut flag: bool = false;
                        let mut yara_checker: Vec<Scanner> = vec![];
                        self.yara_rules.iter().for_each(|a_rule| yara_checker.push(a_rule.scanner().unwrap()));
                        yara_checker.iter_mut().for_each(|yara_scanner| {
                            if let Ok(yara_matches) = yara_scanner.scan_mem(format!("{} {}",
                                        mid_block.0,
                                        each_value
                                    )
                                    .as_bytes()
                            ){
                                if !yara_matches.is_empty() {
                                    if !flag { flag = true; }
                                    yara_matches.into_iter().for_each(|x| {
                                        // println!("[REPORT] Yara matched => {}\n=>\t{}", x.identifier, self.path_filename);
                                        if !matched_rules_names.contains(format!("[{}]",
                                                    x.identifier
                                                )
                                                .as_str()
                                        ){
                                            matched_rules_names.push_str(format!("[{}]",
                                                        x.identifier
                                                    )
                                                    .as_str()
                                            );
                                        }
                                    });
                                }
                            };
                        });
                        if flag {
                            let _ = buf_writer.write_all(format!("{};{};{};true;{}\n",
                                        file_path.as_str(),
                                        mid_block.0,
                                        each_value,
                                        matched_rules_names.as_str()
                                    )
                                    .as_bytes()
                            );
                        }
                        else {
                            let _ = buf_writer.write_all(format!("{};{};{};false;\n",
                                        file_path.as_str(),
                                        mid_block.0,
                                        each_value
                                    )
                                    .as_bytes()
                            );
                        }
                    }
                });
            });
        });
    }

    fn create_key_3values_table_ref(&self,
            table_to_create: String,
            entries: Vec<(String, String, String, String)>,
            headers: (String, String, String, String)
    ){
        let query_table = format!("CREATE TABLE '{table_to_create}' ({} TEXT, {} TEXT, {} TEXT, {} TEXT)",
                headers.0,
                headers.1,
                headers.2,
                headers.3
        );
        let _ = self.connx.execute(query_table);
        let query_insert = format!("INSERT INTO '{table_to_create}' ({}, {}, {}, {}) VALUES (:key, :val1, :val2, :val3)",
                headers.0,
                headers.1,
                headers.2,
                headers.3
        );
        let mut statement = self.connx.prepare(query_insert).unwrap();
        entries.into_iter().for_each(|a_volume| {
            let _ = statement.bind(&[(":key", a_volume.0.as_str()),
                    (":val1", a_volume.1.as_str()),
                    (":val2", a_volume.2.as_str()),
                    (":val3", a_volume.3.as_str())
                    ][..]
            );
            while let Ok(State::Row) = statement.next() {}
            let _ = statement.reset();
        });
    }

    fn compare_key_3values(&self,
            file_path: String,
            table_to_select: String,
            entries: Vec<(String, String, String, String)>,
            header: String
    ){
        let query = format!("SELECT * FROM '{}' WHERE {}=:key",
                table_to_select,
                header
        );
        let mut stmt = self.connx.prepare(query).unwrap();
        let mut buf_writer = match self.create_bufwriter(&file_path) {
            Ok(x) => x,
            Err(err) => panic!("{}", err),
        };
        let _ = buf_writer.write_all(format!("file_name;{};{};{};{};yara_match;yara_rulename\n",
                    stmt.column_name(0).unwrap_or("setting_name"),
                    stmt.column_name(1).unwrap_or("setting_config1"),
                    stmt.column_name(2).unwrap_or("setting_config2"),
                    stmt.column_name(3).unwrap_or("setting_config3")
                )
                .as_bytes()
        );
        entries.into_iter().for_each(|each_entry| {
            let mut flag: bool = false;
            let _ = stmt.bind((":key",
                    each_entry.0.as_str()
            ));
            while let Ok(State::Row) = stmt.next() {
                let values: (String, String, String) = (stmt.read(1).unwrap(),
                        stmt.read(2).unwrap(),
                        stmt.read(3).unwrap()
                );
                if each_entry.1 == values.0 &&
                        each_entry.2 == values.1 &&
                        each_entry.3 == values.2
                {
                    flag = true;
                }
            }
            if !flag {
                let mut matched_rules_names = String::new();
                flag = false;
                let mut yara_checker: Vec<Scanner> = vec![];
                self.yara_rules.iter().for_each(|a_rule| yara_checker.push(a_rule.scanner().unwrap()));
                yara_checker.iter_mut().for_each(|yara_scanner| {
                    if let Ok(yara_matches) = yara_scanner.scan_mem(format!("{} {} {} {}",
                                each_entry.0,
                                each_entry.1,
                                each_entry.2,
                                each_entry.3
                            )
                            .as_bytes()
                    ){
                        if !yara_matches.is_empty() {
                            if !flag { flag = true; }
                            yara_matches.into_iter().for_each(|x| {
                                // println!("[REPORT] Yara matched => {}\n=>\t{}", x.identifier, self.path_filename);
                                if !matched_rules_names.contains(format!("[{}]",
                                            x.identifier
                                        )
                                        .as_str()
                                ){
                                    matched_rules_names.push_str(format!("[{}]",
                                                x.identifier
                                            )
                                            .as_str()
                                    );
                                }
                            });
                        }
                    };
                });
                if flag {
                    let _ = buf_writer.write_all(format!("{};{};{};{};{};true;{}\n",
                                file_path.as_str(),
                                each_entry.0,
                                each_entry.1,
                                each_entry.2,
                                each_entry.3,
                                matched_rules_names.as_str()
                            )
                            .as_bytes()
                    );
                }
                else {
                    let _ = buf_writer.write_all(format!("{};{};{};{};{};false;\n",
                                file_path.as_str(),
                                each_entry.0,
                                each_entry.1,
                                each_entry.2,
                                each_entry.3
                            )
                            .as_bytes()
                    );
                }
            }
            let _ = stmt.reset();
        });
    }

    fn create_5values_block_table_ref(&self,
            table_to_create: String,
            entries: Vec<[String; 5]>,
            headers: (String, String, String, String, String)
    ){
        let query_table = format!("CREATE TABLE '{table_to_create}' ({} TEXT, {} TEXT, {} TEXT, {} TEXT, {} TEXT)",
                headers.0,
                headers.1,
                headers.2,
                headers.3,
                headers.4
        );
        let _ = self.connx.execute(query_table);
        let query_insert = format!("INSERT INTO '{table_to_create}' ({0}, {1}, {2}, {3}, {4}) VALUES (:{0}, :{1}, :{2}, :{3}, :{4})",
                headers.0,
                headers.1,
                headers.2,
                headers.3,
                headers.4
        );
        let mut statement = self.connx.prepare(query_insert).unwrap();
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

    fn compare_5values_block(&self,
            file_path: String,
            entries: Vec<[String; 5]>,
            table_to_select: String,
            header: String
    ){
        let query = format!("SELECT * FROM '{}' WHERE {}=:key",
                table_to_select,
                header
        );
        let mut stmt = self.connx.prepare(query).unwrap();
        let mut buf_writer = match self.create_bufwriter(&file_path) {
            Ok(x) => x,
            Err(err) => panic!("{}", err),
        };
        let _ = buf_writer.write_all(format!("file_name;{};{};{};{};{};yara_match;yara_rulename\n",
                    stmt.column_name(0).unwrap_or("setting_config1"),
                    stmt.column_name(1).unwrap_or("setting_config2"),
                    stmt.column_name(2).unwrap_or("setting_config3"),
                    stmt.column_name(3).unwrap_or("setting_config4"),
                    stmt.column_name(4).unwrap_or("setting_config5")
                )
                .as_bytes()
        );
        entries.into_iter().for_each(|blocks| {
            let mut flag: bool = false;
            let _ = stmt.bind((":key",
                    blocks[0].as_str()
            ));
            while let Ok(State::Row) = stmt.next() {
                let values: (String, String, String, String) = (stmt.read(1).unwrap(),
                        stmt.read(2).unwrap(),
                        stmt.read(3).unwrap(),
                        stmt.read(4).unwrap()
                );
                if values.0 == blocks[1] &&
                        values.1 == blocks[2] &&
                        values.2 == blocks[3] &&
                        values.3 == blocks[4]
                {
                    flag = true;
                }
            }
            if !flag {
                let mut matched_rules_names = String::new();
                flag = false;
                let mut yara_checker: Vec<Scanner> = vec![];
                self.yara_rules.iter().for_each(|a_rule| yara_checker.push(a_rule.scanner().unwrap()));
                yara_checker.iter_mut().for_each(|yara_scanner| {
                    if let Ok(yara_matches) = yara_scanner.scan_mem(format!("{} {} {} {} {}",
                                blocks[0],
                                blocks[1],
                                blocks[2],
                                blocks[3],
                                blocks[4]
                            )
                            .as_bytes()
                    ){
                        if !yara_matches.is_empty() {
                            if !flag { flag = true; }
                            yara_matches.into_iter().for_each(|x| {
                                if !matched_rules_names.contains(format!("[{}]",
                                            x.identifier
                                        )
                                        .as_str()
                                ){
                                    matched_rules_names.push_str(format!("[{}]", 
                                                x.identifier
                                            )
                                            .as_str()
                                    );
                                }
                            });
                        }
                    };
                });
                if flag {
                    let _ = buf_writer.write_all(format!("{};{};{};{};{};{};true;{}\n",
                                file_path.as_str(),
                                blocks[0],
                                blocks[1],
                                blocks[2],
                                blocks[3],
                                blocks[4],
                                matched_rules_names.as_str()
                            )
                            .as_bytes()
                    );
                }
                else {
                    let _ = buf_writer.write_all(format!("{};{};{};{};{};{};false;\n",
                                file_path.as_str(),
                                blocks[0],
                                blocks[1],
                                blocks[2],
                                blocks[3],
                                blocks[4]
                            )
                            .as_bytes()
                    );
                }
            }
            let _ = stmt.reset();
        });
    }

    fn compare_binary_hash(&self,
            file_path: String,
            entries: (String, String),
            // table_to_select: String,
            // header: String
    ){
        let table_to_select: String = String::from("binaries_hashes");
        let query = format!("SELECT * FROM '{}' WHERE key=:key",
                table_to_select);
        let mut stmt = self.connx.prepare(query.as_str()).unwrap();
        let mut buf_writer = match self.create_bufwriter(&file_path) {
            Ok(x) => x,
            Err(err) => panic!("{}", err),
        };
        let _ = buf_writer.write_all("file_name;sha256_sum;yara_match;yara_rulename\n".as_bytes());
        let _ = stmt.bind((":key",
                entries.0.as_str())
        );
        let mut flag: bool = false;
        while let Ok(State::Row) = stmt.next() {
            let value: String = stmt.read(1).unwrap();
            if value == entries.1.to_string() {
                flag = true;
            }
        }
        let _ = stmt.reset();
        if !flag {
            let mut matched_rules_names = String::new();
            flag = false;
            let mut yara_checker: Vec<Scanner> = vec![];
            self.yara_rules.iter().for_each(|a_rule| yara_checker.push(a_rule.scanner().unwrap()));
            yara_checker.iter_mut().for_each(|yara_scanner| {
                if let Ok(yara_matches) = yara_scanner.scan_mem(format!("{} {}",
                        entries.0,
                        entries.1).as_bytes()
                ){
                    if !yara_matches.is_empty() {
                        if !flag { flag = true; }
                        yara_matches.into_iter().for_each(|x| {
                            if !matched_rules_names.contains(format!("[{}]",
                                    x.identifier).as_str()
                            ){
                                matched_rules_names.push_str(format!("[{}]",
                                            x.identifier
                                        )
                                    .as_str()
                                );
                            }
                        });
                    }
                };
            });
            if flag {
                let _ = buf_writer.write_all(format!("{};{};{};true;{}\n",
                            file_path.as_str(),
                            entries.0,
                            entries.1,
                            matched_rules_names.as_str()
                        )
                        .as_bytes()
                );
            }
            else {
                let _ = buf_writer.write_all(format!("{};{};{};false;\n",
                            file_path.as_str(),
                            entries.0,
                            entries.1
                        )
                        .as_bytes()
                );
            }
        }
    }

    fn parse_getprop(&self, read_buffer: BufReader<File>) -> Vec<(String, String)> {
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
                        caps.name("part2").map_or("".to_string(), |m| String::from(m.as_str()))
                ),
                None => { continue; },
            };
            results.push(catches);
        }
        results
    }
    
    fn parse_settings(&self,
            read_buffer: BufReader<File>) -> Vec<(String, String)>
    {
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
            results.push((val1.to_string(),
                    val2.to_string())
            );
        }
        results
    }
    
    fn parse_df_ah(&self,
            read_buffer: BufReader<File>) -> Vec<(String, String)>
    {
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
                results.push((first.to_string(),
                        last.to_string())
                );
            }
        }
        results
    }
    
    fn parse_id(&self,
            read_buffer: BufReader<File>) -> Vec<Vec<(String, Vec<String>)>>
    {
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
                temp_vec.push(( group_name.to_string(),
                        gathered_users )
                );
                results.push(temp_vec);
            });
        }
        results
    }
    
    fn parse_mount(&self,
            read_buffer: BufReader<File>) -> Vec<(String, String, String, String)>
    {
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
                    caps.name("OPTIONS").map_or("".to_string(), |m| m.as_str().to_string())
                ),
                None => { continue; },
            };
            results.push(values);
        }
        results
    }
    
    fn parse_ps(&self,
            read_buffer: BufReader<File>) -> Vec<(String, String, String, String)>
    {
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
                    caps.name("CMD").map_or("".to_string(), |m| m.as_str().to_string())
                ),
                None => { continue; },
            };
            results.push(values);
        }
        results
    }
    
    fn parse_services(&self,
            read_buffer: BufReader<File>) -> Vec<(String, String)>
    {
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
                        caps.name("SVCVAL").map_or("", |m| m.as_str())
                ),
                None => { continue; },
            };
            results.push(( values.0.to_string(),
                    values.1.to_string() )
            );
        }
        results
    }
    
    fn parse_list(&self,
            read_buffer: BufReader<File>) -> Vec<(String, String)>
    {
        let mut results: Vec<(String, String)> = vec![];
        for line in read_buffer.lines() {
            let line_str = match line {
                Ok(x) => x,
                Err(_err) => String::from(""),
            };
            let splitted_str: Vec<String> = line_str.split(":").map(|x| x.to_string()).collect();
            results.push(( splitted_str.first().unwrap().to_string(),
                    splitted_str.last().unwrap().to_string() )
            );
        }
        results
    }
    
    fn parse_permissions_list(&self,
            read_buffer: BufReader<File>) -> Vec<[String; 5]>
    {
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

    fn android_file_selector(&self,
            buf_reader: BufReader<File>,
            file_path: String)
    {
        let path_filename = Path::new(&file_path);
        match path_filename.file_name() {
            Some(x) => {
                let mut splited_str = x.to_str().unwrap().split(".");
                let parted = splited_str.next().unwrap();
                if parted == "getprop"  {
                    self.compare_key_value(String::from(path_filename.to_str().unwrap()),
                            self.parse_getprop(buf_reader),
                            parted.to_string()
                    );
                }
                else if parted.starts_with("settings_") ||
                        parted.starts_with("printenv.txt")
                {
                    self.compare_key_value(String::from(path_filename.to_str().unwrap()),
                            self.parse_settings(buf_reader),
                            parted.to_string()
                    );
                }
                else if parted == "df_ah" {
                    self.compare_key_value(String::from(path_filename.to_str().unwrap()),
                            self.parse_df_ah(buf_reader),
                            parted.to_string()
                    );
                }
                else if parted == "services" {
                    self.compare_key_value(String::from(path_filename.to_str().unwrap()),
                            self.parse_services(buf_reader),
                            parted.to_string()
                    );
                }
                else if parted == "id" {
                    self.compare_key_xvalues(String::from(path_filename.to_str().unwrap()),
                            self.parse_id(buf_reader),
                            parted.to_string()
                    );
                }
                else if parted == "mount" {
                    self.compare_key_3values(String::from(path_filename.to_str().unwrap()),
                            parted.to_string(),
                            self.parse_mount(buf_reader),
                            "name".to_string()
                    );
                }
                else if parted == "ps" {
                    self.compare_key_3values(String::from(path_filename.to_str().unwrap()),
                            parted.to_string(),
                            self.parse_ps(buf_reader),
                            "uid".to_string()
                    );
                }
                else if parted == "pm_list_permissions-f" {
                    self.compare_5values_block(String::from(path_filename.to_str().unwrap()),
                            self.parse_permissions_list(buf_reader),
                            parted.to_string(),
                            "permission".to_string()
                    );
                }
                else if parted.starts_with("pm_list_") &
                        !parted.ends_with("users")
                {
                    self.compare_key_value(String::from(path_filename.to_str().unwrap()),
                            self.parse_list(buf_reader),
                            parted.to_string()
                    );
                }
                else {
                    match Regex::new(r"[\\/]system[\\/]bin[\\/](?P<bin_name>.*)$").unwrap().captures(&file_path) {
                        Some(caps) => {
                            self.compare_binary_hash(String::from(path_filename.to_str().unwrap()),
                                    ( caps.name("bin_name").map_or("".to_string(), |m| m.as_str().to_string()),
                                            sha256::try_digest(Path::new(&file_path)).unwrap() )
                            );
                        },
                        _ => (),
                    };
                }
            },
            _ => (),
        };
    }

    fn android_file_reference(&self,
            file_path: String,
            buf_reader: BufReader<File>
    ) {
        let path_filename = Path::new(&file_path);
        match path_filename.file_name() {
            Some(x) => { 
                let mut splited_str = x.to_str().unwrap().split(".");
                let parted = splited_str.next().unwrap();
                if x == "getprop.txt" {
                    self.create_key_value_table_ref(parted.to_string(),
                            self.parse_getprop(buf_reader)
                    );
                }
                else if parted.starts_with("settings_") || parted == "printenv" {
                    self.create_key_value_table_ref(parted.to_string(),
                            self.parse_settings(buf_reader)
                    );
                }
                else if parted.starts_with("df_ah") {
                    self.create_key_value_table_ref(parted.to_string(),
                            self.parse_df_ah(buf_reader)
                    );
                }
                else if parted == "id" {
                    self.create_key_xvalues_table_ref(parted.to_string(),
                            self.parse_id(buf_reader)
                    );
                }
                else if parted == "mount" {
                    let headers: (String, String, String, String) = ( "name".to_string(),
                            "mountpoint".to_string(),
                            "type".to_string(),
                            "options".to_string()
                    );
                    self.create_key_3values_table_ref(parted.to_string(),
                            self.parse_mount(buf_reader),
                            headers
                    );
                }
                else if parted == "ps" {
                    let headers: (String, String, String, String) = ( "uid".to_string(),
                            "pid".to_string(),
                            "ppid".to_string(),
                            "cmd".to_string()
                    );
                    self.create_key_3values_table_ref( parted.to_string(),
                            self.parse_ps(buf_reader),
                            headers
                    );
                }
                else if parted == "services" {
                    self.create_key_value_table_ref(parted.to_string(),
                            self.parse_services(buf_reader)
                    );
                }
                else if parted == "pm_list_permissions-f" {
                    let headers: (String, String, String, String, String) = ( "permission".to_string(),
                            "package".to_string(), "label".to_string(),
                            "description".to_string(),
                            "protectionlevel".to_string()
                    );
                    self.create_5values_block_table_ref(parted.to_string(),
                            self.parse_permissions_list(buf_reader),
                            headers
                        );
                }
                else if parted.starts_with("pm_list_") &
                        !parted.ends_with("users")
                {
                    self.create_key_value_table_ref(parted.to_string(),
                             self.parse_list(buf_reader)
                    );
                }
                else {
                    match Regex::new(r"[\\/]system[\\/]bin[\\/](?P<bin_name>.*)$").unwrap().captures(&file_path) {
                        Some(caps) => {
                            self.create_key_value_table_ref("binaries_hashes".to_string(),
                                    vec![( caps.name("bin_name").map_or("".to_string(), |m| m.as_str().to_string()),
                                            sha256::try_digest(Path::new(&file_path)).unwrap() )
                                    ]
                            );
                        },
                        _ => (),
                    };
                }
            },
            _ => (),
        };
        
    }
    
}

mod yara_customizer{

    use std::{fs::OpenOptions, path::Path, io::{BufRead, BufReader}};
    use yara::{Rules, Compiler};
    use regex::Regex;


    pub fn yara_rules_ingester(paths: Vec<String>) -> Rules
    {
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
            if let Ok(file_handler) = OpenOptions::new()
                    .read(true)
                    .write(false)
                    .create(false)
                    .open(Path::new(&each_path))
            {
                let buf_reader = BufReader::new(file_handler);
                let mut crash_string = String::new();
                let mut crash_ingest_rules: Vec<String> = vec![];
                let mut valid_rule_flag: bool = false;
                buf_reader.lines().into_iter().for_each(|line| {
                    match line {
                        Ok(l) => {
                            let captures = match re.captures(l.as_str()) {
                                Some(caps) => Some((caps.name("global").map_or("".to_string(), |m| String::from(m.as_str())),
                                        caps.name("identifier").map_or("".to_string(), |m| String::from(m.as_str())))
                                ),
                                None => {
                                    None
                                },
                            };
                            let _ = match captures {
                                Some(x) => {
                                    if x.0.is_empty() {
                                        // Si pas global, je traite
                                        if !x.1.is_empty() {
                                            if crash_ingest_rules.contains(&x.1) || 
                                                    ingested_rules.contains(&x.1)
                                            {
                                                valid_rule_flag = false;
                                                println!("[SKIP] Duplicate identifier for rule {}",
                                                        x.1
                                                );
                                                skipped_rules_counter += 1;
                                            }
                                            else {
                                                valid_rule_flag = true;
                                                crash_string.push_str(format!("{}\n",
                                                        l.as_str()).as_str()
                                                );
                                                crash_ingest_rules.push(x.1);
                                            }
                                            // Si  j'ai un rule identifier, je flag et je traite.
                                        }
                                    }
                                    else {
                                        valid_rule_flag = false;
                                        println!("[SKIP] rule {} is global",
                                                x.1.as_str()
                                        );
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
                                            crash_string.push_str(format!("{}\n",
                                                    l.as_str()).as_str()
                                            );
                                        }
                                    }
                                },
                            };
                        },
                        Err(err) => println!("[ERROR] {}",
                                err.to_string()
                        ),
                    };
                });
                let yara_compiler = Compiler::new().unwrap()
                        .add_rules_str(&crash_string);
                match yara_compiler {
                    Ok(yara_compiler) => {
                        let _ = match yara_compiler.compile_rules() {
                            Ok(_) => {
                                concat_rules.push_str(format!("{}\n",
                                        crash_string).as_str()
                                );
                                crash_ingest_rules.into_iter().for_each(|x| {
                                    ingested_rules.push(x);
                                });
                            },
                            Err(err) => {
                                println!("[ERROR {}] on file => {}",
                                        err.kind.to_string(),
                                        each_path.as_str()
                                );
                                inval_rules_counter += 1;
                            },
                        };
                    },
                    Err(_) => {
                        println!("[ERROR Add Rules] => {}",
                                each_path.as_str()
                        );
                        inval_rules_counter += 1;
                    },
                };
            };
        });
        println!("[REPORT] Skipped {}/{2} rule(s) file(s) containing duplicated.\n[REPORT] Skipped {}/{2} rule(s) file(s) containing error(s)",
                skipped_rules_counter,
                inval_rules_counter,
                overall_yara_files
        );
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

    pub fn yara_rules_finder(path:&Path) -> Vec<String>
    {
        let validator_flag: bool = match path.try_exists() {
            Ok(x) => x,
            Err(err) => panic!("[Error] {}", err.to_string()),
        };
        let mut yara_rules_vec: Vec<String> = vec![];
        if validator_flag &&
                path.is_dir() == true
        {
            if let Ok(read_dir) = path.read_dir() {
                read_dir.into_iter().for_each(|each_dir| {
                    if let Ok(each_entry) = each_dir {
                        if each_entry.file_type().unwrap().is_dir() {
                            self::yara_rules_finder(each_entry.path().as_path())
                                    .into_iter().for_each(|each_yara_rules_path|
                            {
                                yara_rules_vec.push(each_yara_rules_path);
                            });
                        }
                        else if each_entry.file_type().unwrap().is_file() &&
                                ( each_entry.path().extension().is_some_and(|x| x.to_str().unwrap() == "yar") || 
                                each_entry.path().extension().is_some_and(|x| x.to_str().unwrap() == "yara") )
                        {
                            yara_rules_vec.push(each_entry.path().to_str().unwrap().to_string());
                        }
                    }
                });
            }
        }
        yara_rules_vec
    }    

}