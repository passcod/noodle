use std::{
    convert::TryFrom,
    net::{Ipv4Addr, Ipv6Addr},
    result::Result as StdResult,
    str::FromStr,
    time::Duration,
};

use argh::FromArgs;
use async_std::task::spawn;
use color_eyre::eyre::{eyre, Result};
use futures::stream::TryStreamExt;
use ipnetwork::IpNetwork;
use pnet::{datalink::interfaces, util::MacAddr};
use rtnetlink::{packet::rtnl::address::nlas::Nla, AddressHandle};

/// Claim an IP for an interface via ARP/NDP. If we hear about someone else claiming the IP, stop.
#[derive(Debug, FromArgs)]
struct Args {
    /// interface to claim on
    #[argh(option)]
    interface: String,

    /// ip (optionally with subnet, defaults to /32) to claim
    #[argh(option)]
    ip: IpNetwork,

    /// interval to send claims
    #[argh(option, from_str_fn(str_to_secs), default = "Duration::from_secs(60)")]
    interval: Duration,

    /// mac address override
    #[argh(option)]
    mac: Option<MacAddr>,
}

fn str_to_secs(s: &str) -> StdResult<Duration, String> {
    u64::from_str(s)
        .map_err(|e| e.to_string())
        .map(Duration::from_secs)
}

#[async_std::main]
async fn main() -> Result<()> {
    color_eyre::install()?;
    let args: Args = argh::from_env();

    if let IpNetwork::V6(_) = args.ip {
        todo!("ipv6/ndp support");
    }

    dbg!(&args);

    let interface = interfaces()
        .into_iter()
        .find(|i| i.name == args.interface)
        .ok_or(eyre!("interface does not exist"))?;
    if interface.mac.is_none() {
        return Err(eyre!("interface does not have a mac address"));
    }
    if interface.is_loopback() {
        return Err(eyre!("cannot use loopback interface"));
    }
    if interface.is_point_to_point() {
        return Err(eyre!("cannot use point-to-point interface"));
    }
    if !interface.is_up() {
        return Err(eyre!("interface must be up"));
    }

    // => spawn off: listen for arp on the interface
    // - if there's a arp for our ip but not our mac, stop noodle

    let (nlconn, nl, _) = rtnetlink::new_connection()?;
    spawn(nlconn);

    let nlah = AddressHandle::new(nl);

    eprintln!("adding ip to interface");
    nlah.add(interface.index, args.ip.ip(), args.ip.prefix())
        .execute()
        .await?;

    // loop: every interval, send arp. start now

    eprintln!("removing ip from interface");
    let mut addrlist = nlah.get().execute();
    while let Some(addr) = addrlist.try_next().await? {
        if addr.header.index != interface.index {
            continue;
        }

        let addrbytes = match addr.nlas.iter().find(|n| matches!(n, Nla::Address(_))) {
            Some(Nla::Address(a)) => a,
            _ => continue,
        };

        match args.ip {
            IpNetwork::V4(ip4) => {
                match <[u8; 4]>::try_from(addrbytes.clone()).map(Ipv4Addr::from) {
                    Ok(ar) if ar == ip4.ip() => nlah.del(addr).execute().await?,
                    _ => continue,
                };
            }
            IpNetwork::V6(ip6) => {
                match <[u8; 16]>::try_from(addrbytes.clone()).map(Ipv6Addr::from) {
                    Ok(ar) if ar == ip6.ip() => nlah.del(addr).execute().await?,
                    _ => continue,
                };
            }
        };
    }

    Ok(())
}
