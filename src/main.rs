// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::{
	convert::TryFrom,
	net::{IpAddr, Ipv4Addr, Ipv6Addr},
	result::Result as StdResult,
	str::FromStr,
	time::Duration,
};

use argh::FromArgs;
use async_std::{
	channel,
	task::{sleep, spawn, spawn_blocking},
};
use color_eyre::eyre::{eyre, Result};
use futures::{future::TryFutureExt, stream::TryStreamExt, try_join};
use pnet::{
	datalink::{channel as datachannel, interfaces, Channel, ChannelType, Config},
	ipnetwork::IpNetwork,
	packet::{
		arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket},
		ethernet::EtherTypes,
		Packet,
	},
	util::MacAddr,
};
use rand::{rngs::OsRng, Rng};
use rtnetlink::{packet::rtnl::address::nlas::Nla, AddressHandle};

const SOURCE_MAIN: &'static str = include_str!("main.rs");
const SOURCE_CARGO: &'static str = include_str!("../Cargo.toml");
const README: &'static str = include_str!("../README.md");

/// Announce an IP for an interface via ARP.
/// If we hear someone else announcing the IP, stop.
/// See more details in README. License: Apache 2.0 OR MIT.
#[derive(Debug, FromArgs)]
struct Args {
	/// interface to announce on (required)
	#[argh(option)]
	interface: Option<String>,

	/// ip (optionally with subnet, defaults to /32) to announce (required)
	#[argh(option)]
	ip: Option<IpNetwork>,

	/// mac address override
	#[argh(option)]
	mac: Option<MacAddr>,

	/// log level (default=info)
	///
	/// [no, error, warn, info, debug, trace]
	#[argh(option, default = "Default::default()")]
	log: LogLevel,

	/// interval in seconds between announcements (default=10)
	#[argh(option, from_str_fn(str_to_secs), default = "Duration::from_secs(10)")]
	interval: Duration,

	/// delay in seconds before sending first announce (default=0/disabled)
	#[argh(option, from_str_fn(str_to_secs), default = "Duration::from_secs(0)")]
	delay: Duration,

	/// add some random [0 - value in seconds] jitter to delay and interval (default=2)
	#[argh(option, from_str_fn(str_to_secs), default = "Duration::from_secs(2)")]
	jitter: Duration,

	/// announce this many times then stop (default=0/disabled)
	#[argh(option, default = "0")]
	count: usize,

	/// control what the competing announcement watcher does when it sees ARP for the same IP but
	/// from a different MAC (default=fail)
	///
	/// [fail: exit with code=17]
	/// [quit: exit with code=0]
	/// [log: don't exit, only log]
	/// [no: don't watch]
	#[argh(option, default = "Default::default()")]
	watch: Watch,

	/// use arp reply instead of request announcements
	#[argh(switch)]
	arp_reply: bool,

	/// shorthand for `--delay=0 --jitter=0 --count=1 --watch=no`
	#[argh(switch)]
	once: bool,

	/// print the source
	#[argh(switch)]
	source: bool,

	/// print the readme
	#[argh(switch)]
	readme: bool,

	/// print the version
	#[argh(switch)]
	version: bool,
}

fn str_to_secs(s: &str) -> StdResult<Duration, String> {
	u64::from_str(s)
		.map_err(|e| e.to_string())
		.map(Duration::from_secs)
}

#[derive(Clone, Copy, Debug)]
enum Watch {
	Fail,
	Quit,
	Log,
	No,
}

impl Default for Watch {
	fn default() -> Self {
		Self::Fail
	}
}

impl FromStr for Watch {
	type Err = String;

	fn from_str(s: &str) -> StdResult<Self, Self::Err> {
		match s.to_ascii_lowercase().as_str() {
			"fail" => Ok(Self::Fail),
			"quit" => Ok(Self::Quit),
			"log" => Ok(Self::Log),
			"no" => Ok(Self::No),
			_ => Err(String::from("invalid --watch value")),
		}
	}
}

#[derive(Clone, Copy, Debug)]
enum LogLevel {
	No,
	Error,
	Warn,
	Info,
	Debug,
	Trace,
}

impl Default for LogLevel {
	fn default() -> Self {
		Self::Info
	}
}

impl FromStr for LogLevel {
	type Err = String;

	fn from_str(s: &str) -> StdResult<Self, Self::Err> {
		match s.to_ascii_lowercase().as_str() {
			"no" | "none" => Ok(Self::No),
			"error" => Ok(Self::Error),
			"warn" | "warning" => Ok(Self::Error),
			"info" => Ok(Self::Info),
			"debug" | "verbose" => Ok(Self::Debug),
			"trace" => Ok(Self::Trace),
			_ => Err(String::from("invalid --log value")),
		}
	}
}

async fn wait(base: Duration, jitter: Duration) {
	match (base.as_secs(), jitter.as_secs()) {
		(0, 0) => {}
		(_, 0) => sleep(base).await,
		_ => {
			sleep(
				base + Duration::from_millis(
					OsRng::default().gen_range(0..u64::try_from(jitter.as_millis()).unwrap()),
				),
			)
			.await
		}
	}
}

#[async_std::main]
async fn main() -> Result<()> {
	color_eyre::install()?;
	let (ip, iface, args) = {
		let mut args: Args = argh::from_env();

		if args.source {
			println!(
				"# Cargo.toml\n{}\n\n# src/main.rs\n{}",
				SOURCE_CARGO, SOURCE_MAIN
			);
			return Ok(());
		}

		if args.readme {
			println!("{}", README);
			return Ok(());
		}

		if args.version {
			println!("{}", env!("CARGO_PKG_VERSION"));
			return Ok(());
		}

		if args.once {
			args.delay = Duration::from_secs(0);
			args.jitter = Duration::from_secs(0);
			args.count = 1;
			args.watch = Watch::No;
		}

		match (args.ip.clone(), args.interface.clone()) {
			(Some(ip), Some(iface)) => (ip, iface, args),
			(Some(_), None) => return Err(eyre!("missing required option: --interface")),
			(None, Some(_)) => return Err(eyre!("missing required option: --ip")),
			(None, None) => return Err(eyre!("missing required options: --interface, --ip")),
		}
	};

	let ethertype = match ip {
		IpNetwork::V4(_) => EtherTypes::Arp,
		IpNetwork::V6(_) => {
			todo!("ipv6/ndp support");
			#[allow(unreachable_code)]
			EtherTypes::Ipv6
		}
	};

	let interface = interfaces()
		.into_iter()
		.find(|i| i.name == iface)
		.ok_or(eyre!("interface does not exist"))?;
	if interface.is_loopback() {
		return Err(eyre!("cannot use loopback interface"));
	}
	if interface.is_point_to_point() {
		return Err(eyre!("cannot use point-to-point interface"));
	}
	if !interface.is_up() {
		return Err(eyre!("interface must be up"));
	}

	let mac = args
		.mac
		.or(interface.mac)
		.ok_or(eyre!("interface does not have a mac address"))?;

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
	let watch = args.watch;
	let listener = spawn_blocking(move || -> Result<()> {
		if let Watch::No = watch {
			return Ok(());
		}

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
	nlah.add(interface.index, ip.ip(), ip.prefix())
		.execute()
		.await?;

	let blaster = spawn(async move {
		if false {
			return Ok(()) as Result<()>;
		}
		wait(args.delay, args.jitter).await;

		let mut n = 0_usize;
		loop {
			let mut buf = vec![0_u8; MutableArpPacket::minimum_packet_size()];
			let mut arp =
				MutableArpPacket::new(&mut buf[..]).ok_or(eyre!("failed to create arp packet"))?;

			let ip4 = match ip.ip() {
				IpAddr::V4(i) => i,
				_ => todo!("ipv6 support"),
			};

			arp.set_protocol_type(EtherTypes::Ipv4);
			arp.set_hardware_type(ArpHardwareTypes::Ethernet);
			arp.set_hw_addr_len(6);
			arp.set_proto_addr_len(4);
			arp.set_sender_hw_addr(mac);
			arp.set_target_hw_addr(mac);
			arp.set_sender_proto_addr(ip4);
			arp.set_target_proto_addr(ip4);
			arp.set_operation(if args.arp_reply {
				ArpOperations::Reply
			} else {
				ArpOperations::Request
			});

			// this isn't async but should be fast compared to the wait
			tx.send_to(arp.packet(), None).transpose()?;

			n = n.saturating_add(1);
			if args.count > 0 && n >= args.count {
				return Ok(());
			}

			wait(args.interval, args.jitter).await;
		}
	});

	if let Err(err) = if let Watch::No = watch {
		try_join!(blaster).map(|_| ())
	} else {
		try_join!(
			terminator.recv().map_err(|e| e.into()).and_then(|_| async {
				Err(eyre!("Ctrl-C received, quitting gracefully")) as Result<()>
			}),
			listener,
			blaster,
		)
		.map(|_| ())
	} {
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

		match ip {
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
