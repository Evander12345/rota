extern crate actix_web;
extern crate actix_rt;
extern crate actix_files;
extern crate chrono;

use actix_web::{HttpServer, App, web, HttpRequest, HttpResponse, Responder};
use std::io;
use chrono::{DateTime, Utc, TimeZone};
use actix_web::http::{StatusCode, HeaderMap};
use std::io::{Read};
use std::str;

const ESPOTA_DIR_PATH: &str = "/root/espota/";


async fn ota(req: HttpRequest) -> impl Responder {
    let headers: &HeaderMap = &req.headers();
    // Before doing anything, authenticate the api key and device type.
    if !check_device_is_allowed(&headers) {
        // Device is not allowed, send 403 Forbidden.
        return HttpResponse::Forbidden().finish()
    }
    if !validate_api_key(&headers) {
        // API key not recognized, send 401 Unauthorized.
        return HttpResponse::Unauthorized().finish()
    }
    // Handle OTA request if client bears key and is esp32/8266
    let mac_addr = extract_mac_addr_string(headers);
    let firmware_version_str = extract_firmware_string(headers);
    println!("Device ID {} validated with api key.", mac_addr);
    let firmware_version = extract_version_from_version_str(firmware_version_str.as_str());
    // If the headers contain the version number then continue parsing update...
    if firmware_version.timestamp() < get_latest_firmware_date(headers).timestamp() {
        let mut buffer:Vec<u8> = Vec::new();
        if let Ok(mut f) = std::fs::File::open(std::path::Path::new(format!("{}.ino.bin", construct_target_firmware_path_string(headers)).as_str())) {
            match f.read_to_end(buffer.as_mut()) {
                Ok(_) => {},
                Err(e) => panic!("Error reading file, {}", e)
            }
        } else {
            panic!("Not accepted.");
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
// This function checks to see if the device is running an outdated version of the firmware.
async fn check_for_firmware_update(req: HttpRequest) -> impl Responder {
    let headers = req.headers();
    let firmware_version_str = extract_firmware_string(headers);
    // First validate the API key.
    if validate_api_key(&headers) {
        let version = extract_version_from_version_str(firmware_version_str.as_ref());
        let latest = get_latest_firmware_date(headers);
        if version.timestamp() < latest.timestamp() {
            HttpResponse::Ok()
        } else {
            HttpResponse::NotModified()
        }
    } else {
        HttpResponse::Forbidden()
    }
}
// This function construct a path to the verion of the firmware the device is set to download in `espota/targets`.
fn construct_target_firmware_path_string(headers: &HeaderMap) -> String {
    // Extract mac address string from request.
    let mac_addr = extract_mac_addr_string(headers);
    // Open up the target firmware file
    if let Ok(f) = std::fs::read_to_string(std::path::Path::new(format!("{}{}", ESPOTA_DIR_PATH, "targets").as_str())) {
        let lines = f.lines();
        for line in lines {
            let split_line: Vec<&str> = line.split(",").collect();
            if split_line[0] == mac_addr.as_str() {
                //println!("{}::{}", &split_line[0], &split_line[1]);
                return format!("{}{}", ESPOTA_DIR_PATH, remove_whitespace(split_line[1]).as_str());
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
    //println!("Validating otadata {}", &req_string);
    let fields: Vec<&str> = req_string.split("?").collect();
    let validating_key = fields[1];
    if let Ok(file) = std::fs::read_to_string(std::path::Path::new(format!("{}{}", ESPOTA_DIR_PATH, "api_keys").as_str())) {
        let mut lines = file.lines();
        lines.any(|elem| elem == validating_key)
    } else {
        panic!("Error finding api_keys");
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
    );
    server.bind(format!("{}:{}", addr, port).as_str())?.run().await
}