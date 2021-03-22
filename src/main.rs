// SPDX-License-Identifier: Apache-2.0 OR MIT

use std::{
	convert::TryFrom,
	io::Write,
	net::{IpAddr, Ipv4Addr, Ipv6Addr},
	process::exit,
	result::Result as StdResult,
	str::FromStr,
	thread::sleep,
	time::Duration,
};

use argh::FromArgs;
use async_std::{
	channel,
	prelude::FutureExt,
	task::{block_on, spawn, spawn_blocking},
};
use chrono::{SecondsFormat, Utc};
use color_eyre::eyre::{eyre, Result};
use env_logger::{Builder as LogBuilder, Target as LogTarget};
use futures::{stream::TryStreamExt, TryFutureExt};
use kv_log_macro::{debug, error, info, warn};
use log::{kv, LevelFilter};
use pnet::{
	datalink::{
		channel as datachannel, interfaces, Channel, ChannelType, Config, NetworkInterface,
	},
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
use pulse::Signal;
use rand::{rngs::OsRng, Rng};
use rtnetlink::{packet::{AddressMessage, rtnl::address::nlas::Nla}, AddressHandle};
use serde::Serialize;

macro_rules! as_display {
	($e:expr) => {
		&$e as &dyn std::fmt::Display
	};
}

const SOURCE_MAIN: &str = include_str!("main.rs");
const SOURCE_CARGO: &str = include_str!("../Cargo.toml");
const README: &str = include_str!("../README.md");

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

	/// target mac override (default=broadcast)
	#[argh(option, default = "MacAddr::broadcast()")]
	target: MacAddr,

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

	/// delay in seconds before watching for competing announcements (default=0/disabled)
	#[argh(option, from_str_fn(str_to_secs), default = "Duration::from_secs(0)")]
	watch_delay: Duration,

	/// add some random [0 - value in seconds] jitter to each interval (default=1)
	#[argh(option, from_str_fn(str_to_secs), default = "Duration::from_secs(1)")]
	jitter: Duration,

	/// announce this many times then stop (default=0/disabled)
	#[argh(option, default = "0")]
	count: usize,

	/// control what the competing announcement watcher does when it sees ARP for the same IP but
	/// from a different MAC (default=fail)
	///
	/// [fail: exit with code=1]
	/// [quit: exit with code=0]
	/// [log: don't exit, only log]
	/// [no: don't watch]
	#[argh(option, default = "Default::default()")]
	watch: Watch,

	/// start the watcher immediately instead of waiting until the first announcement
	#[argh(switch)]
	watch_immediately: bool,

	/// use arp reply instead of request announcements
	#[argh(switch)]
	arp_reply: bool,

	/// don't add/remove the ip to/from the interface
	#[argh(switch)]
	unmanaged_ip: bool,

	/// exit with code=1 if the ip exists on the interface already
	#[argh(switch)]
	die_if_ip_exists: bool,

	/// remove the ip from the interface on exit even when we didn't add it ourselves
	#[argh(switch)]
	remove_pre_existing_ip: bool,

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

impl LogLevel {
	fn install(self) -> Result<()> {
		if let Self::No = self {
			return Ok(());
		}

		let mut log = LogBuilder::new();
		log.target(LogTarget::Stdout);

		if let Self::Trace = self {
			log.filter(None, LevelFilter::Trace);
		} else {
			log.filter(
				Some("noodle"),
				match self {
					Self::Error => LevelFilter::Error,
					Self::Warn => LevelFilter::Warn,
					Self::Info => LevelFilter::Info,
					Self::Debug => LevelFilter::Debug,
					_ => unreachable!(),
				},
			);
		}

		#[derive(Serialize)]
		struct Record<'kv> {
			level: &'static str,
			#[serde(skip_serializing_if = "Option::is_none")]
			module: Option<String>,
			ts: String,
			msg: String,

			#[serde(flatten)]
			#[serde(with = "kv::source::as_map")]
			kvs: &'kv dyn kv::Source,
		}

		log.format(move |mut buf, record| {
			let rec = Record {
				level: record.level().as_str(),
				module: if let Self::Trace = self {
					record.module_path().map(|m| m.to_string())
				} else {
					None
				},
				ts: Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
				msg: record.args().to_string(),
				kvs: record.key_values(),
			};

			serde_json::to_writer(&mut buf, &rec)?;
			writeln!(buf)?;
			Ok(())
		});

		log.try_init()?;

		Ok(())
	}
}

fn wait(d: Duration) {
	if d.as_millis() > 0 {
		debug!("sleeping {:?}", d);
		sleep(d);
	}
}

fn jittered(base: Duration, jitter: Duration) -> Duration {
	match (base.as_secs(), jitter.as_millis()) {
		(0, 0) => Duration::from_secs(0),
		(_, 0) => base,
		(_, j) => {
			base + Duration::from_millis(OsRng::default().gen_range(0..u64::try_from(j).unwrap()))
		}
	}
}

fn main() -> Result<()> {
	// panics+prep errors get color-eyre'd, run errors get logged
	color_eyre::install()?;

	if let Some(p) = prep()? {
		debug!("arguments", {
			ip: &p.0.to_string(),
			interface: &p.1.to_string(),
			mac: &p.2.to_string(),
			ip_managed: p.3,
			args: &format!("{:?}", p.4),
		});

		if let Err(e) = block_on(run(p)) {
			error!("{}", e);
			exit(1);
		}
	}

	Ok(())
}

type Prep = (IpNetwork, NetworkInterface, MacAddr, bool, Args);

fn prep() -> Result<Option<Prep>> {
	let (ip, args) = {
		let mut args: Args = argh::from_env();
		args.log.install()?;

		if args.source {
			println!(
				"# Cargo.toml\n{}\n\n# src/main.rs\n{}",
				SOURCE_CARGO, SOURCE_MAIN
			);
			return Ok(None);
		}

		if args.readme {
			println!("{}", README);
			return Ok(None);
		}

		if args.version {
			println!("{}", env!("CARGO_PKG_VERSION"));
			return Ok(None);
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

		match (args.ip, &args.interface) {
			(Some(ip), Some(_)) => (ip, args),
			(Some(_), None) => return Err(eyre!("missing required option: --interface")),
			(None, Some(_)) => return Err(eyre!("missing required option: --ip")),
			(None, None) => return Err(eyre!("missing required options: --interface, --ip")),
		}
	};

	let interface = interfaces()
		.into_iter()
		.find(|i| Some(&i.name) == args.interface.as_ref())
		.ok_or_else(|| eyre!("interface does not exist"))?;
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
		.ok_or_else(|| eyre!("interface does not have a mac address"))?;

	Ok(Some((ip, interface, mac, !args.unmanaged_ip, args)))
}

async fn run((ip, interface, mac, mut ip_managed, args): Prep) -> Result<()> {
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

		info!("checking if interface has ip", { ip: as_display!(ip), interface: interface.index });
		if find_addr_for_ip(&nlah, interface.clone(), ip).await?.is_some() {
			if args.die_if_ip_exists {
				return Err(eyre!("ip exists on interface, abort"));
			} else {
				warn!("existing ip on the interface");
				if !args.remove_pre_existing_ip {
					ip_managed = false;
				}
			}
		} else {
			info!("adding ip to interface", { ip: as_display!(ip), interface: interface.index });
			nlah.add(interface.index, ip.ip(), ip.prefix())
				.execute()
				.await?;
		}
	}

	let (listener, blaster) = match ip {
		IpNetwork::V4(_) => {
			let (watch_signal, mut watch_pulse) = if args.watch_immediately || args.count == 0 {
				(Signal::pulsed(), None)
			} else {
				let (s, p) = Signal::new();
				(s, Some(p))
			};

			let watch = args.watch;
			let watch_delay = args.watch_delay;

			let listener = spawn_blocking(move || -> Result<()> {
				if let Watch::No = watch {
					return Ok(());
				}

				watch_signal
					.wait()
					.map_err(|_| eyre!("failed to wait on watch signal"))?;
				wait(watch_delay);

				info!("watching for competing arp announcements");

				loop {
					let pkt = rx.next()?;
					let eth = EthernetPacket::new(pkt)
						.ok_or_else(|| eyre!("eth packet buffer too small"))?;
					if eth.get_ethertype() != EtherTypes::Arp {
						continue;
					}

					let pay = eth.payload();
					let arp =
						ArpPacket::new(pay).ok_or_else(|| eyre!("arp packet buffer too small"))?;

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
				wait(args.delay);

				let mut n = 0_usize;
				loop {
					let mut arp_buf = vec![0_u8; MutableArpPacket::minimum_packet_size()];
					let mut arp = MutableArpPacket::new(&mut arp_buf[..])
						.ok_or_else(|| eyre!("failed to create arp packet"))?;

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
						.ok_or_else(|| eyre!("failed to create eth packet"))?;

					eth.set_source(mac);
					eth.set_destination(args.target);
					eth.set_ethertype(EtherTypes::Arp);
					eth.set_payload(arp.packet_mut());

					info!("sending arp packet", {
						n: n,
						src: as_display!(mac),
						dst: as_display!(args.target),
						op: if args.arp_reply { "reply" } else { "request" },
						hw: "ethernet",
						hw_addr: as_display!(mac),
						proto_addr: as_display!(ip4),
						gratuitous: true,
					});
					tx.send_to(eth.packet(), None)
						.transpose()?
						.ok_or_else(|| eyre!("unknown error sending packet"))?;

					n = n.saturating_add(1);
					if args.count > 0 && n >= args.count {
						return Ok(());
					}

					if let Some(pulse) = watch_pulse.take() {
						pulse.pulse();
					}

					wait(jittered(args.interval, args.jitter));
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
		info!("removing ip from interface", { ip: as_display!(ip), interface: interface.index });
		if let Some(addr) = find_addr_for_ip(&nlah, interface, ip).await? {
			nlah.del(addr).execute().await?;
		}
	}

	Ok(())
}

async fn find_addr_for_ip(
	nlah: &AddressHandle,
	interface: NetworkInterface,
	ip: IpNetwork,
) -> Result<Option<AddressMessage>> {
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
					Ok(ar) if ar == ip4.ip() => return Ok(Some(addr)),
					_ => continue,
				};
			}
			IpNetwork::V6(ip6) => {
				match <[u8; 16]>::try_from(addrbytes.clone()).map(Ipv6Addr::from) {
					Ok(ar) if ar == ip6.ip() => return Ok(Some(addr)),
					_ => continue,
				};
			}
		};
	}

	Ok(None)
}
