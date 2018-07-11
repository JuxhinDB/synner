pub mod packet {
    extern crate rand;
    extern crate pnet;
    extern crate pnet_base;
    extern crate pnet_packet;
    extern crate pnet_datalink;
    extern crate pnet_transport;

    use std::net::{IpAddr, Ipv4Addr};

    use self::pnet_base::{MacAddr};
    use self::pnet_packet::tcp::{MutableTcpPacket, TcpFlags, TcpOption};
    use self::pnet_packet::ethernet::{MutableEthernetPacket, EtherTypes};
    use self::pnet_packet::ip::{IpNextHeaderProtocols};
    use self::pnet_packet::ipv4::{MutableIpv4Packet, Ipv4Flags};
    use self::pnet_datalink::{Channel, NetworkInterface};

    #[derive(Debug)]
    pub struct PartialPacketData<'a> {
        pub destination_ip: Ipv4Addr,
        pub iface_ip: Ipv4Addr,
        pub iface_name: &'a String,
        pub iface_src_mac: &'a MacAddr
    }


    pub fn build_random_packet(partial_packet: &PartialPacketData) -> Option<[u8; 66]> {
        const ETHERNET_HEADER_LEN: usize = 14;
        const IPV4_HEADER_LEN: usize = 20;
        const TCP_HEADER_LEN: usize = 32;

        let mut tmp_packet = [0u8; ETHERNET_HEADER_LEN + IPV4_HEADER_LEN + TCP_HEADER_LEN];
        
        // Setup Ethernet header
        {
            let mut eth_header = MutableEthernetPacket::new(&mut tmp_packet[..ETHERNET_HEADER_LEN]).unwrap();

            eth_header.set_destination(MacAddr::new(8, 0, 39, 203, 157, 11));
            eth_header.set_source(*partial_packet.iface_src_mac);
            eth_header.set_ethertype(EtherTypes::Ipv4);
        }

        // Setup IP header
        {
            let mut ip_header = MutableIpv4Packet::new(&mut tmp_packet[ETHERNET_HEADER_LEN..(ETHERNET_HEADER_LEN + IPV4_HEADER_LEN)]).unwrap();
            ip_header.set_header_length(69);
            ip_header.set_total_length(52);
            ip_header.set_fragment_offset(16384);
            ip_header.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
            ip_header.set_source(partial_packet.iface_ip);
            ip_header.set_destination(partial_packet.destination_ip);
            ip_header.set_identification(rand::random::<u16>());
            ip_header.set_ttl(128);
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
            tcp_header.set_sequence(rand::random::<u32>());

            tcp_header.set_options(&vec![TcpOption::wscale(8), TcpOption::sack_perm(), TcpOption::mss(1460), TcpOption::nop(), TcpOption::nop()]);

            let checksum = pnet_packet::tcp::ipv4_checksum(&tcp_header.to_immutable(), &partial_packet.iface_ip, &partial_packet.destination_ip);
            tcp_header.set_checksum(checksum);        
        }

        Some(tmp_packet)    
    }

    pub fn send_tcp_packet(destination_ip: Ipv4Addr, interface: String) {
        let interfaces = pnet_datalink::interfaces();
        println!("{:?}", &interfaces);

        let interfaces_name_match = |iface: &NetworkInterface| iface.name == interface;
        let interface = interfaces
            .into_iter()
            .filter(interfaces_name_match)
            .next()
            .unwrap();

        let iface_ip = match interface.ips[0].ip() {
            IpAddr::V4(ipv4) => ipv4,
            _ => panic!("ERR - Interface IP is IPv6 (or unknown) which is not currently supported"),
        };

        let partial_packet: PartialPacketData = PartialPacketData {
            destination_ip: destination_ip,
            iface_ip,
            iface_name: &interface.name,
            iface_src_mac: &interface.mac.unwrap()
        };

        let (mut tx, _) = match pnet_datalink::channel(&interface, Default::default()) {
            Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => panic!("Unknown channel type"),
            Err(e) => panic!("Error happened {}", e),
        };

        let mut count = 0;

        loop {
            count += 1;
            tx.send_to(&build_random_packet(&partial_packet).unwrap().to_vec(), None);

            if &count % 10000 == 0 {
                println!("Sent packet #{}", &count);
            }        
        }
    }    
}