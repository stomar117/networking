use etherparse::{IcmpEchoHeader, Icmpv4Slice, Icmpv4Type, PacketBuilder, TcpHeaderSlice};
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
                    let mut ibuf =
                        vec![kflags.to_be_bytes().to_vec(), iproto.to_be_bytes().to_vec()]
                            .into_iter()
                            .flatten()
                            .collect::<Vec<u8>>();
                    if let Icmpv4Type::EchoRequest(req) = icmph.icmp_type() {
                        match PacketBuilder::ipv4(iph.destination(), iph.source(), 64)
                            .icmpv4(Icmpv4Type::EchoReply(IcmpEchoHeader {
                                id: req.id,
                                seq: req.seq,
                            }))
                            .write(&mut ibuf, icmph.payload())
                        {
                            Ok(_) => {
                                println!(
                                    "header: {:?} len: {}",
                                    icmph.header(),
                                    icmph.header_len()
                                );
                                nic.send(ibuf.as_slice()).unwrap();
                            }
                            Err(e) => {
                                eprintln!("Error: failed to craft packet: {:?}", e);
                            }
                        }
                    }
                } else {
                    println!();
                }
            }
            Err(e) => eprintln!("Skipping packet due to: {:?}", e),
        }
    }
}
