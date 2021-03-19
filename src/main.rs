// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::{
	convert::TryFrom,
	net::{IpAddr, Ipv4Addr, Ipv6Addr},
	result::Result as StdResult,
	str::FromStr,
	thread::sleep,
	time::Duration,
};

use argh::FromArgs;
use async_std::{
	channel,
	prelude::FutureExt,
	task::{spawn, spawn_blocking},
};
use color_eyre::eyre::{eyre, Result};
use femme::LevelFilter;
use futures::{stream::TryStreamExt, TryFutureExt};
use kv_log_macro::{debug, info, warn};
use pnet::{
	datalink::{channel as datachannel, interfaces, Channel, ChannelType, Config},
	ipnetwork::IpNetwork,
	packet::{
		arp::{
			ArpHardwareType, ArpHardwareTypes, ArpOperation, ArpOperations, ArpPacket,
			MutableArpPacket,
		},
		ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket},
		MutablePacket, Packet,
	},
	util::MacAddr,
};
use rand::{rngs::OsRng, Rng};
use rtnetlink::{packet::rtnl::address::nlas::Nla, AddressHandle};

macro_rules! as_display {
	($e:expr) => {
		&$e as &dyn std::fmt::Display
	};
}

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

	/// don't add/remove the ip to/from the interface
	#[argh(switch)]
	unmanaged_ip: bool,

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
			"warn" | "warning" => Ok(Self::Warn),
			"info" => Ok(Self::Info),
			"debug" | "verbose" => Ok(Self::Debug),
			"trace" => Ok(Self::Trace),
			_ => Err(String::from("invalid --log value")),
		}
	}
}

impl From<LogLevel> for LevelFilter {
	fn from(ll: LogLevel) -> Self {
		match ll {
			LogLevel::No => Self::Off,
			LogLevel::Error => Self::Error,
			LogLevel::Warn => Self::Warn,
			LogLevel::Info => Self::Info,
			LogLevel::Debug => Self::Debug,
			LogLevel::Trace => Self::Trace,
		}
	}
}

fn wait(base: Duration, jitter: Duration) {
	let slep = match (base.as_secs(), jitter.as_millis()) {
		(0, 0) => None,
		(_, 0) => Some(base),
		(_, j) => Some(
			base + Duration::from_millis(OsRng::default().gen_range(0..u64::try_from(j).unwrap())),
		),
	};

	if let Some(d) = slep {
		debug!("sleeping {:?}", d);
		sleep(d);
	}
}

#[async_std::main]
async fn main() -> Result<()> {
	color_eyre::install()?;
	let (ip, iface, ip_managed, args) = {
		let mut args: Args = argh::from_env();
		femme::with_level(args.log.into());

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

		if args.jitter > args.interval {
			return Err(eyre!("jitter > interval makes no sense"));
		}

		if args.delay > Duration::from_secs(60 * 60 * 24) {
			warn!("delay > 24h is probably a mistake");
		}

		if args.interval > Duration::from_secs(60 * 60 * 24) {
			warn!("interval > 24h is probably a mistake");
		}

		match (args.ip.clone(), args.interface.clone()) {
			(Some(ip), Some(iface)) => (ip, iface, !args.unmanaged_ip, args),
			(Some(_), None) => return Err(eyre!("missing required option: --interface")),
			(None, Some(_)) => return Err(eyre!("missing required option: --ip")),
			(None, None) => return Err(eyre!("missing required options: --interface, --ip")),
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
			channel_type: ChannelType::Layer2,
			promiscuous: true,
			..Default::default()
		},
	)? {
		Channel::Ethernet(tx, rx) => (tx, rx),
		_ => unimplemented!("internal: unhandled datachannel type"),
	};

	// TODO: use dialectic session types?
	let (oconnor, terminator) = channel::bounded(1);
	ctrlc::set_handler(move || {
		oconnor
			.try_send(())
			.expect("failed to exit, so exiting harder (unclean)");
	})?;

	let (nlconn, nl, _) = rtnetlink::new_connection()?;
	let nlah = AddressHandle::new(nl);

	if ip_managed {
		debug!("starting netlink connection");
		spawn(nlconn);

		info!("adding ip to interface", { ip: as_display!(ip), interface: interface.index });
		nlah.add(interface.index, ip.ip(), ip.prefix())
			.execute()
			.await?;
	}

	let (listener, blaster) = match ip {
		IpNetwork::V4(_) => {
			let watch = args.watch;
			let listener = spawn_blocking(move || -> Result<()> {
				if let Watch::No = watch {
					return Ok(());
				}

				info!("watching for competing arp announcements");

				loop {
					let pkt = rx.next()?;
					let eth =
						EthernetPacket::new(pkt).ok_or(eyre!("eth packet buffer too small"))?;
					if eth.get_ethertype() != EtherTypes::Arp {
						continue;
					}

					let pay = eth.payload();
					let arp = ArpPacket::new(pay).ok_or(eyre!("arp packet buffer too small"))?;

					let op = match arp.get_operation() {
						ArpOperations::Reply => String::from("reply"),
						ArpOperations::Request => String::from("request"),
						ArpOperation(n) => format!("unknown: {}", n),
					};

					let hw = match arp.get_hardware_type() {
						ArpHardwareTypes::Ethernet => String::from("ethernet"),
						ArpHardwareType(n) => format!("unknown: {}", n),
					};

					let gratuitous = arp.get_sender_proto_addr() == arp.get_target_proto_addr();

					debug!("read arp packet", {
						src: as_display!(eth.get_source()),
						dst: as_display!(eth.get_destination()),
						op: as_display!(op),
						hw: as_display!(hw),
						proto: as_display!(arp.get_protocol_type()),
						sender_hw: as_display!(arp.get_sender_hw_addr()),
						sender_proto: as_display!(arp.get_sender_proto_addr()),
						target_hw: as_display!(arp.get_target_hw_addr()),
						target_proto: as_display!(arp.get_target_proto_addr()),
						gratuitous: gratuitous,
					});

					if gratuitous
						&& arp.get_sender_proto_addr() == ip.ip()
						&& arp.get_sender_hw_addr() != mac
					{
						match watch {
							Watch::No => unreachable!(),
							Watch::Fail => {
								return Err(eyre!(
									"received competing announce! src={} mac={}",
									eth.get_source(),
									arp.get_sender_hw_addr()
								))
							}
							Watch::Quit => {
								info!("received competing announce!", {
									src: as_display!(eth.get_source()),
									mac: as_display!(arp.get_sender_hw_addr()),
								});
								return Ok(());
							}
							Watch::Log => {
								warn!("received competing announce!", {
									src: as_display!(eth.get_source()),
									mac: as_display!(arp.get_sender_hw_addr()),
								});
							}
						}
					}
				}
			});

			let blaster = spawn_blocking(move || -> Result<()> {
				wait(args.delay, args.jitter);

				let mut n = 0_usize;
				loop {
					let mut arp_buf = vec![0_u8; MutableArpPacket::minimum_packet_size()];
					let mut arp = MutableArpPacket::new(&mut arp_buf[..])
						.ok_or(eyre!("failed to create arp packet"))?;

					let ip4 = match ip.ip() {
						IpAddr::V4(i) => i,
						_ => unreachable!(),
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

					let mut eth_buf = vec![
						0_u8;
						MutableEthernetPacket::minimum_packet_size()
							+ MutableArpPacket::minimum_packet_size()
					];
					let mut eth = MutableEthernetPacket::new(&mut eth_buf)
						.ok_or(eyre!("failed to create eth packet"))?;

					let broadcast = MacAddr::broadcast();
					eth.set_source(mac);
					eth.set_destination(broadcast);
					eth.set_payload(arp.packet_mut());

					info!("sending arp packet", {
						src: as_display!(mac),
						dst: as_display!(broadcast),
						op: if args.arp_reply { "reply" } else { "request" },
						hw: "ethernet",
						hw_addr: as_display!(mac),
						proto_addr: as_display!(ip4),
						gratuitous: true,
					});
					tx.send_to(eth.packet(), None)
						.transpose()?
						.ok_or(eyre!("unknown error sending packet"))?;

					n = n.saturating_add(1);
					if args.count > 0 && n >= args.count {
						return Ok(());
					}

					wait(args.interval, args.jitter);
				}
			});

			(listener, blaster)
		}
		IpNetwork::V6(_) => todo!("ipv6 support"),
	};

	if let Err(err) = terminator
		.recv()
		.map_err(|e| e.into())
		.race(listener)
		.race(blaster)
		.await
	{
		eprintln!("{:?}", err);
	}

	if ip_managed {
		info!("removing ip from interface", { ip: &ip as &dyn std::fmt::Display, interface: interface.index });
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
	}

	Ok(())
}
