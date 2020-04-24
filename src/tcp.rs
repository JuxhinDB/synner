

pub mod packet {
    extern crate rand;
    extern crate pnet;
    extern crate pnet_base;
    extern crate pnet_packet;
    extern crate pnet_datalink;
    extern crate pnet_transport;

    use std::net::{IpAddr, Ipv4Addr};

    use self::pnet_packet::tcp::{MutableTcpPacket, TcpFlags, TcpOption};
    use self::pnet_packet::ethernet::{MutableEthernetPacket, EtherTypes};
    use self::pnet_packet::ip::{IpNextHeaderProtocols};
    use self::pnet_packet::ipv4::{MutableIpv4Packet, Ipv4Flags};
    use self::pnet_datalink::{Channel, NetworkInterface, MacAddr};

    pub struct PartialTCPPacketData<'a> {
        pub destination_ip: Ipv4Addr,
        pub iface_ip: Ipv4Addr,
        pub iface_name: &'a String,
        pub iface_src_mac: &'a MacAddr,
    }


    pub fn build_random_packet(partial_packet: &PartialTCPPacketData, tmp_packet: &mut [u8]) {
        const ETHERNET_HEADER_LEN: usize = 14;
        const IPV4_HEADER_LEN: usize = 20;

        // Setup Ethernet header
        {
            let mut eth_header = MutableEthernetPacket::new(&mut tmp_packet[..ETHERNET_HEADER_LEN]).unwrap();

            eth_header.set_destination(MacAddr::broadcast());
            eth_header.set_source(*partial_packet.iface_src_mac);
            eth_header.set_ethertype(EtherTypes::Ipv4);
        }

        // Setup IP header
        {
            let mut ip_header = MutableIpv4Packet::new(&mut tmp_packet[ETHERNET_HEADER_LEN..(ETHERNET_HEADER_LEN + IPV4_HEADER_LEN)]).unwrap();
            ip_header.set_header_length(69);
            ip_header.set_total_length(52);
            ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
            ip_header.set_source(partial_packet.iface_ip);
            ip_header.set_destination(partial_packet.destination_ip);
            ip_header.set_identification(rand::random::<u16>());
            ip_header.set_ttl(64);
            ip_header.set_version(4);
            ip_header.set_flags(Ipv4Flags::DontFragment);

            let checksum = pnet_packet::ipv4::checksum(&ip_header.to_immutable());
            ip_header.set_checksum(checksum);
        }

        // Setup TCP header
        {
            let mut tcp_header = MutableTcpPacket::new(&mut tmp_packet[(ETHERNET_HEADER_LEN + IPV4_HEADER_LEN)..]).unwrap();

            tcp_header.set_source(rand::random::<u16>());
            tcp_header.set_destination(rand::random::<u16>());

            tcp_header.set_flags(TcpFlags::SYN);
            tcp_header.set_window(64240);
            tcp_header.set_data_offset(8);
            tcp_header.set_urgent_ptr(0);
            tcp_header.set_sequence(0);

            tcp_header.set_options(&[TcpOption::mss(1460), TcpOption::sack_perm(),  TcpOption::nop(), TcpOption::nop(), TcpOption::wscale(7)]);

            let checksum = pnet_packet::tcp::ipv4_checksum(&tcp_header.to_immutable(), &partial_packet.iface_ip, &partial_packet.destination_ip);
            tcp_header.set_checksum(checksum);
        }
    }

    pub fn send_tcp_packets(destination_ip: Ipv4Addr, interface: String, count: u32) {
        let interfaces = pnet_datalink::interfaces();

        println!("List of Available Interfaces\n");

        for interface in interfaces.iter() {
            let iface_ip = interface.ips.iter().next().map(|x| match x.ip() {
                IpAddr::V4(ipv4) => Some(ipv4),
                _ => panic!("ERR - Interface IP is IPv6 (or unknown) which is not currently supported"),
            });

            println!("Interface name: {:?}\nInterface MAC: {:?}\nInterface IP: {:?}\n", &interface.name, &interface.mac.unwrap(), iface_ip)
        }

        let interfaces_name_match = |iface: &NetworkInterface| iface.name == interface;
        let interface = interfaces
            .into_iter()
            .filter(interfaces_name_match)
            .next()
            .expect(&format!("could not find interface by name {}", interface));

        let iface_ip = match interface.ips.iter().nth(0).expect(&format!("the interface {} does not have any IP addresses", interface)).ip() {
            IpAddr::V4(ipv4) => ipv4,
            _ => panic!("ERR - Interface IP is IPv6 (or unknown) which is not currently supported"),
        };

        let partial_packet: PartialTCPPacketData = PartialTCPPacketData {
            destination_ip: destination_ip,
            iface_ip,
            iface_name: &interface.name,
            iface_src_mac: &interface.mac.unwrap(),
        };

        let (mut tx, _) = match pnet_datalink::channel(&interface, Default::default()) {
            Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => panic!("Unknown channel type"),
            Err(e) => panic!("Error happened {}", e),
        };

        for i in 0..count {

            if &i % 10000 == 0 {
                println!("Sent {:?} packets", &i);
            }

            tx.build_and_send(1, 66, &mut |packet: &mut [u8]| {
                build_random_packet(&partial_packet, packet);
            });
        }
    }
}
