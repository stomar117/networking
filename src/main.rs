mod icmp;

use etherparse::{Icmpv4Slice, TcpHeaderSlice};
use std::io::Result;
use tun_tap::Iface;

fn main() -> Result<()> {
    let nic = Iface::new("tun0", tun_tap::Mode::Tun).unwrap();
    let mut buff = [0; 1504];
    loop {
        let bytes = nic.recv(&mut buff[..])?;
        let kflags = u16::from_be_bytes([buff[0], buff[1]]);
        let iproto = u16::from_be_bytes([buff[2], buff[3]]);
        match etherparse::Ipv4HeaderSlice::from_slice(&buff[4..bytes]) {
            Ok(iph) => {
                print!(
                    "{:?} -> {:?} => ",
                    iph.source_addr(),
                    iph.destination_addr()
                );
                if let Ok(tcph) = TcpHeaderSlice::from_slice(&buff[4 + iph.slice().len()..bytes]) {
                    println!("{:?}", tcph);
                } else if let Ok(icmph) =
                    Icmpv4Slice::from_slice(&buff[4 + iph.slice().len()..bytes])
                {
                    icmp::reply(&nic, iph.destination(), iph.source(), icmph, kflags, iproto);
                } else {
                    println!();
                }
            }
            Err(e) => eprintln!("Skipping packet due to: {:?}", e),
        }
    }
}
