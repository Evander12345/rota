# rota - An OTA server for the ESP8266 and ESP32 microcontrollers, written in Rust.

## Installation
**R**ust **OTA** can be installed by running

`git clone https://github.com/Evander12345/rota.git`

followed by
 
`cargo install --path=rota`

## Configuation
Currently the configuration is rather complicated... I am trying to streamline this process currently. Before running cargo install you should change the constant to point towards some directory, an example of this directory (espota_example) is included.
To get an idea on how to set up the server, checkout my [blog post](https://blog.evanolder.com/2020/04/30/creating-a-self-hosted-esp8266-esp32-over-the-air-programming-platform/).