extern crate pnet;
extern crate pnet_base;
extern crate pnet_datalink;
extern crate pnet_packet;
extern crate pnet_transport;
extern crate rand;
extern crate synner;

use synner::tcp::packet::send_tcp_packets;

use std::env;
use std::net::Ipv4Addr;

fn print_help() {
    println!("Usage: ./synner [destination_ip] [interface_name] [number_of_packets (optional)]");
}

fn parse_arguments() -> Result<(Ipv4Addr, String, u64), &'static str> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 3 {
        println!("Too few arguments. See usage:");
        print_help();
        panic!();
    }

    let dst_ip = args[1].parse::<Ipv4Addr>().unwrap();
    let iface = args[2].to_string();
    let num_packets = if args.len() > 3 {
        let result = u64::from_str_radix(&args[3], 10);
        if let Err(_) = result {
            println!("ERROR: Number of packets must be a number");
            panic!();
        }

        result.unwrap()
    } else {
        1
    };

    Ok((dst_ip, iface, num_packets))
}

fn main() {
    let parsed_args = parse_arguments().unwrap();

    send_tcp_packets(parsed_args.0, parsed_args.1, parsed_args.2);

    println!("Sent {} packet(s)", &parsed_args.2);
}
