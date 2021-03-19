// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::{
	convert::TryFrom,
	net::{Ipv4Addr, Ipv6Addr},
	result::Result as StdResult,
	str::FromStr,
	time::Duration,
};

use argh::FromArgs;
use async_std::{
	channel,
	task::{spawn, spawn_blocking},
};
use color_eyre::eyre::{eyre, Result};
use futures::{future::TryFutureExt, stream::TryStreamExt, try_join};
use pnet::{
	datalink::{channel as datachannel, interfaces, Channel, ChannelType, Config},
	ipnetwork::IpNetwork,
	packet::{
		arp::{ArpOperations, ArpPacket},
		ethernet::EtherTypes,
	},
	util::MacAddr,
};
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

	/// mac address override
	#[argh(option)]
	mac: Option<MacAddr>,

	/// log level (default=info)
	#[argh(option)]
	log: String,

	/// interval in seconds to send claims (default=10)
	#[argh(option, from_str_fn(str_to_secs), default = "Duration::from_secs(10)")]
	interval: Duration,

	/// delay in seconds before sending first claim (default=0/disabled)
	#[argh(option, from_str_fn(str_to_secs), default = "Duration::from_secs(0)")]
	delay: Duration,

	/// add some random [0 - value in seconds] jitter to delay and interval (default=2)
	#[argh(option, from_str_fn(str_to_secs), default = "Duration::from_secs(2)")]
	jitter: Duration,

	/// blast advertisements this many times then stop (default=0/disabled)
	#[argh(option)]
	count: usize,

	/// control the advertisement watcher (default=fail)
	///
	/// - `fail` (default): exit with status 17 if we see an advertisement for this IP by another MAC address
	/// - `quit`:
	/// - `log`:
	/// - `no`:
	#[argh(option)]
	watch: String,

	/// shorthand for `--count=1 --watch=no`
	#[argh(option)]
	once: bool,
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

	let ethertype = match args.ip {
		IpNetwork::V4(_) => EtherTypes::Arp,
		IpNetwork::V6(_) => {
			todo!("ipv6/ndp support");
			EtherTypes::Ipv6
		}
	};

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

	let (mut tx, mut rx) = match datachannel(
		&interface,
		Config {
			channel_type: ChannelType::Layer3(ethertype.0),
			promiscuous: true,
			..Default::default()
		},
	)? {
		Channel::Ethernet(tx, rx) => (tx, rx),
		_ => unimplemented!("internal: unhandled datachannel type"),
	};

	let (oconnor, terminator) = channel::bounded(1);
	ctrlc::set_handler(move || {
		oconnor
			.try_send(())
			.expect("failed to exit, so exiting harder (unclean)");
	})?;

	// ctrl-c / sig{term,int} handler

	// => spawn off: listen for arp on the interface
	// - if there's a arp for our ip but not our mac, stop noodle
	let listener = spawn_blocking(move || -> Result<()> {
		loop {
			match rx.next()? {
				pkt => match ethertype {
					EtherTypes::Arp => {
						let arp =
							ArpPacket::new(pkt).ok_or(eyre!("arp packet buffer too small"))?;
						let op = match arp.get_operation() {
							ArpOperations::Reply => "reply",
							ArpOperations::Request => "request",
							_ => "unk",
						};
						eprintln!("arp {}: {:?}", op, arp);
					}
					EtherTypes::Ipv6 => todo!("v6 support"),
					_ => unreachable!(),
				},
			}
		}
	});

	let (nlconn, nl, _) = rtnetlink::new_connection()?;
	spawn(nlconn);

	let nlah = AddressHandle::new(nl);

	eprintln!("adding ip to interface");
	nlah.add(interface.index, args.ip.ip(), args.ip.prefix())
		.execute()
		.await?;

	// loop: every interval, send arp. start now

	if let Err(err) = try_join!(
		terminator.recv().map_err(|e| e.into()).and_then(|_| async {
			Err(eyre!("Ctrl-C received, quitting gracefully")) as Result<()>
		}),
		listener
	) {
		eprintln!("{:?}", err);
	}

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
