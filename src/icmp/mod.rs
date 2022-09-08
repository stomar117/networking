use etherparse::{
    IcmpEchoHeader, Icmpv4Slice,
    Icmpv4Type::{EchoReply, EchoRequest},
    PacketBuilder,
};
use tun_tap::Iface;

pub fn reply(
    nic: &Iface,
    src: [u8; 4],
    dst: [u8; 4],
    request_header: Icmpv4Slice,
    kflags: u16,
    iproto: u16,
) {
    let mut ibuf: Vec<_> = vec![kflags.to_be_bytes().to_vec(), iproto.to_be_bytes().to_vec()]
        .into_iter()
        .flatten()
        .collect();
    if let EchoRequest(req) = request_header.icmp_type() {
        match PacketBuilder::ipv4(src, dst, 64)
            .icmpv4(EchoReply(IcmpEchoHeader {
                id: req.id,
                seq: req.seq,
            }))
            .write(&mut ibuf, request_header.payload())
        {
            Ok(_) => {
                println!(
                    "header: {:?} len: {}",
                    request_header.header(),
                    request_header.header_len()
                );
                nic.send(ibuf.as_slice()).unwrap();
            }
            Err(e) => {
                eprintln!("Error: failed to craft packet: {:?}", e);
            }
        }
    }
}
