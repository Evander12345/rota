#[macro_use]
extern crate serde_derive;

extern crate actix_web;
extern crate chrono;
extern crate config;
extern crate dirs;

use actix_web::{HttpServer, App, web, HttpRequest, HttpResponse, Responder};
use std::io;
use chrono::{DateTime, Utc, TimeZone};
use actix_web::http::{StatusCode, HeaderMap};
use std::io::{Read, Write};
use std::str;
use config::{Config};
use std::convert::From;
use std::path::Path;
use std::fs::File;
use std::error::Error;

#[derive(Serialize, Deserialize)]
struct EspDevice {
    device_id: String,
    device_alias: String,
    target_firmware: String
}
// This function generates a string representing the path to the configuration file.
fn get_config_path() -> String {
    let mut path = match dirs::config_dir() {
        Some(buf) => buf,
        _ => panic!("Error"),
    };
    path.push(Path::new("rota/"));
    String::from(path.to_str().unwrap())
}
// The main OTA function, handles route /ota
async fn ota(req: HttpRequest) -> impl Responder {
    // Get the headers from the request.
    let headers: &HeaderMap = &req.headers();
    // Before doing anything, authenticate the api key and device type.
    if !check_device_is_allowed(&headers) {
        // Device is not allowed, send 403 Forbidden. Print IP if it exists. Fail2ban?
        match headers.get("x-real-ip") {
            Some(ip) => println!("Device with IP {} rejected.", ip.to_str().unwrap()),
            _ => {}
        };
        return HttpResponse::Forbidden().finish()
    }
    if !validate_api_key(&headers) {
        // API key not recognized, send 401 Unauthorized.
        match headers.get("x-real-ip") {
            Some(ip) => println!("Device with IP {} failed to authenticate.", ip.to_str().unwrap()),
            _ => {}
        };
        return HttpResponse::Unauthorized().finish()
    }
    // Handle OTA request if client bears key and is esp32/8266
    let mac_addr = extract_mac_addr_string(headers);
    let firmware_version_str = extract_firmware_string(headers);
    println!("Device ID {} validated with api key.", mac_addr);
    // Warn if device is sending API key over an unencrypted HTTP connection, if the header is found that is.
    match client_using_https(&headers) {
        false => println!("WARNING: Client {} is sending API key over an unencrypted HTTP request.", mac_addr),
        _ => {}
    };
    let firmware_version = extract_version_from_version_str(firmware_version_str.as_str());
    // If the headers contain the version number then continue parsing update...
    if firmware_version.timestamp() < get_latest_firmware_date(headers).timestamp() {
        let mut buffer:Vec<u8> = Vec::new();
        if let Ok(mut f) = std::fs::File::open(std::path::Path::new(format!("{}.ino.bin", construct_target_firmware_path_string(headers)).as_str())) {
            match f.read_to_end(buffer.as_mut()) {
                Ok(_) => {},
                Err(e) => panic!("Error reading binary file file, {}", e)
            }
        } else {
            panic!("Error opening binary file.");
        }
        match headers.get("x-esp8266-sta-mac") {
            Some(mac) => println!("Sending firmware dated {} to ESP8266 {} running firmware dated {}", get_latest_firmware_date(headers), mac.clone().to_str().unwrap(), firmware_version),
            _ => match headers.get("x-esp32-sta-mac") {
                Some(mac) => println!("Sending firmware dated {} to ESP32 {} running firmware dated {}", get_latest_firmware_date(headers), mac.clone().to_str().unwrap(), firmware_version),
                _ => println!("Device not recognized?")
            }
        }
        HttpResponse::build(StatusCode::from_u16(200).unwrap()).body(buffer)
    } else {
        match headers.get("x-esp8266-sta-mac") {
            Some(mac) => println!("ESP8266 {} running latest firmware already.", mac.clone().to_str().unwrap()),
            _ => match headers.get("x-esp32-sta-mac") {
                Some(mac) => println!("ESP32 {} running latest firmware already.", mac.clone().to_str().unwrap()),
                _ => println!("Device not recognized?")
            }
        }
        HttpResponse::NotModified().finish()
    }
}
// This function checks to see if the device is running an outdated version of the firmware.
async fn check_for_firmware_update(req: HttpRequest) -> impl Responder {
    // Get the headers from the request.
    let headers: &HeaderMap = &req.headers();
    // Before doing anything, authenticate the api key and device type.
    if !check_device_is_allowed(&headers) {
        // Device is not allowed, send 403 Forbidden. Print IP if it exists. Fail2ban?
        match headers.get("x-real-ip") {
            Some(ip) => println!("Device with IP {} rejected.", ip.to_str().unwrap()),
            _ => {}
        };
        return HttpResponse::Forbidden().finish()
    }
    if !validate_api_key(&headers) {
        // API key not recognized, send 401 Unauthorized.
        match headers.get("x-real-ip") {
            Some(ip) => println!("Device with IP {} failed to authenticate.", ip.to_str().unwrap()),
            _ => {}
        };
        return HttpResponse::Unauthorized().finish()
    }
    let firmware_version_str = extract_firmware_string(headers);
    let version = extract_version_from_version_str(firmware_version_str.as_ref());
    let latest = get_latest_firmware_date(headers);
    if version.timestamp() < latest.timestamp() {
        HttpResponse::Ok().finish()
    } else {
        HttpResponse::NotModified().finish()
    }
}
// This function is used to register devices via mac address. Saves to configuration file.
async fn register_device(req: HttpRequest) -> impl Responder {
    // Get the headers from the request.
    let headers: &HeaderMap = &req.headers();
    // Before doing anything, authenticate the api key.
    if !validate_api_key(&headers) {
        // API key not recognized, send 401 Unauthorized.
        match headers.get("x-real-ip") {
            Some(ip) => println!("Device with IP {} failed to authenticate.", ip.to_str().unwrap()),
            _ => {}
        };
        return HttpResponse::Unauthorized().finish()
    }

    // Write mac address into configuration file.
    if let Some(header) = headers.get("esp-device-id") {
        let esp_id = match header.to_str() {
            Ok(id) => id,
            Err(e) => panic!("Device ID is invalid {}", e)
        };
        // Generate Device Struct
        let device_to_save = EspDevice {
            device_id: esp_id.parse().unwrap(),
            device_alias: String::from("UNASSIGNED"),
            target_firmware: String::from("UNASSIGNED")
        };
        save_settings(device_to_save)
    }
    HttpResponse::Ok().body(String::from("Wrote device into settings."))
}
// This function is used to assign a target firmware to a device via device id. Saves to configuration file.
async fn assign_firmware(req: HttpRequest) -> impl Responder {
    // Get the headers from the request.
    let headers: &HeaderMap = &req.headers();
    // Before doing anything, authenticate the api key.
    if !validate_api_key(&headers) {
        // API key not recognized, send 401 Unauthorized.
        match headers.get("x-real-ip") {
            Some(ip) => println!("Device with IP {} failed to authenticate.", ip.to_str().unwrap()),
            _ => {}
        };
        return HttpResponse::Unauthorized().finish()
    }
    // Write target target firmware into configuration file.
    if let Some(header) = headers.get("esp-device-id") {
        let esp_id = match header.to_str() {
            Ok(id) => id,
            Err(e) => panic!("Device ID is invalid {}", e)
        };
        if let Some(header) = headers.get("esp-target-firmware") {
            let esp_firmware = match header.to_str() {
                Ok(firmware) => firmware,
                Err(e) => panic!("Device ID is invalid {}", e)
            };
            // Load device configuration file into memory
            let devices: Vec<EspDevice> = load_deice_config().unwrap();
            let dev_index = devices.iter().position(|e| e.device_id == esp_id).unwrap();
            let device_to_save = EspDevice {
                device_id: devices.get(dev_index).unwrap().device_id.to_string(),
                device_alias: devices.get(dev_index).unwrap().device_alias.to_string(),
                target_firmware: esp_firmware.to_string()
            };
            purge_device_by_index(dev_index);
            save_settings(device_to_save);
        }
    }
    HttpResponse::Ok().body(String::from("Assigned firmware to device."))
}
// This function is used to assign an alias to a device via device id. Saves to configuration file.
async fn assign_alias(req: HttpRequest) -> impl Responder {
    // Get the headers from the request.
    let headers: &HeaderMap = &req.headers();
    // Before doing anything, authenticate the api key.
    if !validate_api_key(&headers) {
        // API key not recognized, send 401 Unauthorized.
        match headers.get("x-real-ip") {
            Some(ip) => println!("Device with IP {} failed to authenticate.", ip.to_str().unwrap()),
            _ => {}
        };
        return HttpResponse::Unauthorized().finish()
    }
    // Write target target firmware into configuration file.
    if let Some(header) = headers.get("esp-device-id") {
        let esp_id = match header.to_str() {
            Ok(id) => id,
            Err(e) => panic!("Device ID is invalid {}", e)
        };
        if let Some(header) = headers.get("esp-alias") {
            let esp_alias = match header.to_str() {
                Ok(alias) => alias,
                Err(e) => panic!("Device ID is invalid {}", e)
            };
            // Load device configuration file into memory
            let devices: Vec<EspDevice> = load_deice_config().unwrap();
            let dev_index = devices.iter().position(|e| e.device_id == esp_id).unwrap();
            let device_to_save = EspDevice {
                device_id: devices.get(dev_index).unwrap().device_id.to_string(),
                device_alias: esp_alias.to_string(),
                target_firmware: devices.get(dev_index).unwrap().device_id.to_string()
            };
            purge_device_by_index(dev_index);
            save_settings(device_to_save);
        }
    }
    HttpResponse::Ok().body(String::from("Assigned alias to device."))
}
// This function removes a device from the configuration file by index.
fn purge_device_by_index(index: usize) {
    // Load config into memory in the form of Vec<EspDevice>
    let mut configuration: Vec<EspDevice> = load_deice_config().unwrap();
    configuration.remove(index);
    // Save the device configuration
    match try_save(configuration) {
        Ok(_) => {},
        Err(e) => panic!("Error saving configuration, {}", e)
    }
}
// This functions writes the devices back into the settings file.
fn save_settings(to_save: EspDevice) {
    // Load config into memory in the form of Vec<EspDevice>
    let mut configuration: Vec<EspDevice> = load_deice_config().unwrap();

    // Check to see if the device already exists before saving it again.
    let mut exists: bool = false;
    for host in configuration.iter() {
        if to_save.device_id == host.device_id {
            exists = true;
        }
    }
    if !exists {
        configuration.push(to_save);
    } else {
        println!("Device already in configuration file!");
    }

    // Save the device configuration
    match try_save(configuration) {
        Ok(_) => {},
        Err(e) => panic!("Error saving configuration, {}", e)
    }
}
// This function attempts to save the configuration into a file.
fn try_save(configuration: std::vec::Vec<EspDevice>) -> std::io::Result<()>{
    let mut path = match dirs::home_dir() {
        Some(buf) => buf,
        _ => panic!("Error getting home directory"),
    };
    path.push(Path::new(".config/rota_example/devices.toml"));
    // Create the config file. Destroys the old copy.
    let mut save_file = File::create(path)?;
    // Write bundled device values into the file...
    let devices = bundle_devices(configuration);
    save_file.write_all(format!("device_id = '{}'\ndevice_alias = '{}'\ntarget_firmware = '{}'", devices.device_id, devices.device_alias, devices.target_firmware).into_bytes().as_ref())?;
    save_file.sync_data()?;
    Ok(())
}
// This function bundles devices together into one string, making it easy to save to a file.
fn bundle_devices(devices: std::vec::Vec<EspDevice>) -> EspDevice {
    let mut device_id = String::from("");
    let mut device_alias = String::from("");
    let mut target_firmware = String::from("");

    // Bundle all host fields into one string using the pipe character as the delimiter.
    for device in devices.iter() {
        device_id.push_str(format!("{}{}",device.clone().device_id.as_str(), "|").as_str());
        device_alias.push_str(format!("{}{}",device.clone().device_alias.as_str(), "|").as_str());
        target_firmware.push_str(format!("{}{}",device.clone().target_firmware.as_str(), "|").as_str());
    }

    // Remove trailing pipe from fields
    device_id = device_id[0..device_id.len() - 1].parse().unwrap();
    device_alias = device_alias[0..device_alias.len() - 1].parse().unwrap();
    target_firmware = target_firmware[0..target_firmware.len() - 1].parse().unwrap();

    EspDevice{
        device_id,
        device_alias,
        target_firmware,
    }
}
// This function loads settings config file into a `Vec<espDevices>`
fn load_deice_config() -> Result<std::vec::Vec<EspDevice>, Box<dyn Error>> {
    let mut settings = Config::new();
    let mut path = match dirs::home_dir() {
        Some(buf) => buf,
        _ => panic!("Error"),
    };

    path.push(Path::new(".config/rota_example/devices.toml"));
    match settings.merge(config::File::from(path)) {
        Ok(_) => {},
        Err(e) => println!("Error merging configuration file {}", e)
    }
    let ids: std::vec::Vec<String> = to_string_vec(settings.get::<String>("device_id")?.split("|").collect());
    let aliases: std::vec::Vec<String> = to_string_vec(settings.get::<String>("device_alias")?.split("|").collect());
    let firmwares: std::vec::Vec<String> = to_string_vec(settings.get::<String>("target_firmware")?.split("|").collect());

    let mut r_devices: std::vec::Vec<EspDevice> = vec!();
    for i in 0..ids.len() {
        r_devices.push(EspDevice {
            device_id: String::from(ids[i].clone()),
            device_alias: String::from(aliases[i].clone()),
            target_firmware: String::from(firmwares[i].clone()),
        });
    }

    Ok(r_devices)
}
// This function converts a vec<str> to a vec<String>
fn to_string_vec(as_an_str: std::vec::Vec<&str>) -> std::vec::Vec<String>  {
    as_an_str.into_iter().map(|elem| String::from(elem)).collect()
}
// This function parses the `x-forwarded-proto` header to determine http protocol of client. Returns true for HTTPS, false for HTTP.
fn client_using_https(headers: &HeaderMap) -> bool {
    match headers.get("x-forwarded-proto") {
        Some(val) => match val.to_str().unwrap() {
            "https" => true,
            _ => false
        }
        _ => false // Assume worst case if we cannot tell.
    }
}
// This function constructs a path to the version of the firmware the device is set to download in `espota/targets`.
fn construct_target_firmware_path_string(headers: &HeaderMap) -> String {
    // Extract mac address string from request.
    let mac_addr = extract_mac_addr_string(headers);
    // Open up the target firmware file
    if let Ok(f) = std::fs::read_to_string(std::path::Path::new(format!("{}{}", get_config_path(), "targets").as_str())) {
        let lines = f.lines();
        for line in lines {
            let split_line: Vec<&str> = line.split(",").collect();
            if split_line[0] == mac_addr.as_str() {
                //println!("{}::{}", &split_line[0], &split_line[1]);
                return format!("{}{}", get_config_path(), remove_whitespace(split_line[1]).as_str());
            }
        }
        panic!("Path to target binary could not be created.");
    } else {
        panic!("Error reading targets file.");
    }
}
// This function removes whitespace from str.
fn remove_whitespace(s: &str) -> String {
    s.chars().filter(|c| !c.is_whitespace()).collect()
}
// This function extracts the version header string.
fn extract_firmware_string(headers: &HeaderMap) -> String {
    match headers.get("x-esp8266-version") {
        Some(val) => String::from(val.to_str().unwrap().clone()),
        _ => {
            // If no ESP8266 headers are detected, then try for ESP32 headers.
            match headers.get("x-esp32-version") {
                Some(val) => String::from(val.to_str().unwrap().clone()),
                _ => panic!("Device not an ESP8266/32")
            }
        }
    }
}
// This function extracts the mac address header string.
fn extract_mac_addr_string(headers: &HeaderMap) -> String {
    match headers.get("x-esp8266-sta-mac") {
        Some(val) => String::from(val.to_str().unwrap().clone()),
        _ => {
            // If no ESP8266 headers are detected, then try for ESP32 headers.
            match headers.get("x-esp32-sta-mac") {
                Some(val) => String::from(val.to_str().unwrap().clone()),
                _ => panic!("Device not an ESP8266/32")
            }
        }
    }
}
// This function retrieves the latest date for the firmware the device is set to download in `espota/targets` as a `chrono::DateTime<Utc>`.
fn get_latest_firmware_date(headers: &HeaderMap) -> DateTime<Utc> {
    if let Ok(file) = std::fs::read_to_string(std::path::Path::new(format!("{}.ct", construct_target_firmware_path_string(headers)).as_str())) {
        let lines: Vec<&str> = file.lines().collect();
        let line: String = lines.into_iter().map(String::from).collect();
        let year: i32 = match line[8..12].to_string().parse() {
            Ok(res) => res,
            _ => panic!("Error parsing stored year.")
        };
        let month: u32 = match &line[1..4] {
            "Jan" => 1,
            "Feb" => 2,
            "Mar" => 3,
            "Apr" => 4,
            "May" => 5,
            "Jun" => 6,
            "Jul" => 7,
            "Aug" => 8,
            "Sep" => 9,
            "Oct" => 10,
            "Nov" => 11,
            "Dec" => 12,
            _ => {panic!("Error parsing stored month.")}
        };
        let day: u32 = match &line[5..6] {
            " " => match line[6..7].parse() {
                Ok(res) => res,
                _ => panic!("Error parsing stored day.")
            }
            _ => match line[5..7].parse() {
                Ok(res) => res,
                _ => panic!("Error parsing stored day.")
            }
        };
        let hour: u32 = match line[19..21].parse() {
            Ok(res) => res,
            _ => panic!("Error parsing stored hour.")
        };
        let minute: u32 = match line[22..24].parse() {
            Ok(res) => res,
            _ => panic!("Error parsing stored minute.")
        };
        let second: u32 = match line[25..27].parse() {
            Ok(res) => res,
            _ => panic!("Error parsing stored second.")
        };
        Utc.ymd(year, month, day).and_hms(hour, minute, second)
    } else {
        panic!("Error reading compile time");
    }
}
// This function validates the clients api key.
fn validate_api_key(headers: &HeaderMap) -> bool {
    //let api_key = firmware_version_str.split("?").collect::<Vec<&str>>()[1];
    let req_string = extract_firmware_string(headers);
    let fields: Vec<&str> = req_string.split("?").collect();
    let validating_key = fields[1];
    if let Ok(file) = std::fs::read_to_string(std::path::Path::new(format!("{}{}", get_config_path().as_str(), "api_keys").as_str())) {
        let mut lines = file.lines();
        lines.any(|elem| elem == validating_key)
    } else {
        panic!("Error finding api_keys");
    }
}
// This function checks to see if the device is an ESP8266 or an ESP32.
fn check_device_is_allowed(headers: &HeaderMap) -> bool {
    match headers.get("x-esp8266-sta-mac") {
        Some(_mac) => true,
        _ => match headers.get("x-esp32-sta-mac") {
            Some(_mac) => true,
            _ => false,
        }
    }
}
// This function extracts the currently running version from headers as a `chrono::DateTime<Utc>`.
fn extract_version_from_version_str(req_string: &str) -> DateTime<Utc> {
    let year: i32 = req_string[7..11].parse().clone().unwrap();
    let month: u32 = match &req_string[0..3] {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => {panic!("Error Parsing Month")}
    };
    let day: u32 = match &req_string[4..5] {
        " " => req_string[5..6].parse().clone().unwrap(),
        _ => req_string[4..6].parse().clone().unwrap()
    };
    let hour: u32 = req_string[12..14].parse().unwrap();
    let minute: u32 = req_string[15..17].parse().unwrap();
    let second: u32 = req_string[18..20].parse().unwrap();
    Utc.ymd(year, month, day).and_hms(hour, minute, second)
}
#[actix_rt::main]
async fn main() -> io::Result<()> {
    // Values used to set the listening address and port of the Actix-Web Server
    let port: String = String::from("80");
    let addr: String = String::from("localhost");
    println!("Actix-web listening on {}:{}", addr, port);
    let server = HttpServer::new(||
        App::new()
            .route("/ota", web::get().to(ota))
            .route("/checkforupdate", web::get().to(check_for_firmware_update))
            .route("/register", web::post().to(register_device))
            .route("/assignfirmware", web::post().to(assign_firmware))
            .route("/assignalias", web::post().to(assign_alias))
    );
    server.bind(format!("{}:{}", addr, port).as_str())?.run().await
}