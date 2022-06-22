use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::unix::prelude::{IntoRawFd, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::{
	env,
	fs::File,
	os::unix::prelude::{FromRawFd, RawFd},
};

use crate::{console, devices, hermit, mounts};
use crate::{flags, paths, rootfs};
use crate::{namespaces, network};
use capctl::prctl;
use nix::sched::CloneFlags;
use nix::unistd::{Gid, Pid, Uid};
use oci_spec::runtime;
use oci_spec::runtime::Spec;

// #[derive(Clone, Copy, Debug, Default)]
// struct SocketPair {
// 	parent: RawFd,
// 	child: RawFd,
// }

// impl From<(i32, i32)> for SocketPair {
// 	fn from(tuple: (i32, i32)) -> Self {
// 		SocketPair {
// 			parent: RawFd::from(tuple.0),
// 			child: RawFd::from(tuple.1),
// 		}
// 	}
// }

#[derive(Clone, Copy, Debug)]
enum InitStage {
	Parent,
	Child,
}

#[derive(Clone, Debug)]
struct InitConfig {
	spec: Spec,
	cloneflags: CloneFlags,
	rootfs: String,
	bundle_rootfs: String,
	is_hermit_container: bool,
}

#[derive(Clone, Debug)]
struct SetupArgs {
	stage: InitStage,
	init_pipe: RawFd,
	config: InitConfig,
}

const STACK_SIZE: usize = 16384 * 2;

#[repr(align(16))]
struct CloneArgs {
	stack: [u8; STACK_SIZE],
	args: SetupArgs,
	child_func: Box<dyn Fn(SetupArgs) -> isize>,
}

pub fn init_container() {
	// This implements the init process functionality,
	// analogous to https://github.com/opencontainers/runc/blob/master/libcontainer/nsenter/nsexec.c

	// During this process, it:
	// - unshares from the user namespaces
	// - unshares from all other requested namespaces
	// - creates a child process in a new PID namespace
	// - reports back the child-PID to the create process
	// - Waits for the exec-fifo to open during the runh start call
	let pipe_fd: i32 = env::var("RUNH_INITPIPE")
		.expect("No init pipe given!")
		.parse()
		.expect("RUNH_INITPIPE was not an integer!");

	//TODO: Ensure we are in a cloned binary (prevent CVE-2019-5736)

	//Detect hermit container
	let is_hermit_container: bool = env::var("RUNH_HERMIT_CONTAINER")
		.expect("No value for RUNH_HERMIT_CONTAINER set!")
		.parse()
		.expect("RUNH_HERMIT_CONTAINER was not a boolean value!");

	let mut init_pipe = unsafe { File::from_raw_fd(pipe_fd) };
	write!(init_pipe, "\0").expect("Unable to write to init-pipe!");

	//Read rootfs from init pipe
	let mut size_buffer = [0u8; std::mem::size_of::<usize>()];
	init_pipe
		.read_exact(&mut size_buffer)
		.expect("Could not read message size from init-pipe!");
	let message_size = usize::from_le_bytes(size_buffer);
	debug!("Rootfs-path lenght: {}", message_size);

	let mut rootfs_path_buffer = vec![0; message_size as usize];
	init_pipe
		.read_exact(&mut rootfs_path_buffer)
		.expect("Could not read rootfs-path from init pipe!");
	let rootfs_path =
		String::from_utf8(rootfs_path_buffer).expect("Could not parse rootfs-path as string!");
	debug!("read rootfs from init_pipe: {}", rootfs_path);

	//Read bundle rootfs from init pipe
	let mut bundle_rootfs_path = rootfs_path.clone();
	if is_hermit_container {
		init_pipe
			.read_exact(&mut size_buffer)
			.expect("Could not read message size from init-pipe!");
		let message_size = usize::from_le_bytes(size_buffer);
		debug!("Bundle rootfs path lenght: {}", message_size);

		let mut bundle_rootfs_path_buffer = vec![0; message_size as usize];
		init_pipe
			.read_exact(&mut bundle_rootfs_path_buffer)
			.expect("Could not read bundle rootfs path from init pipe!");
		bundle_rootfs_path = String::from_utf8(bundle_rootfs_path_buffer)
			.expect("Could not parse bundle rootfs path as string!");
		debug!(
			"read bundle rootfs path from init_pipe: {}",
			bundle_rootfs_path
		);
	}

	//Read spec file
	debug!("read config from spec file");
	let spec_fd: i32 = env::var("RUNH_SPEC_FILE")
		.expect("No spec file given!")
		.parse()
		.expect("RUNH_SPEC_FILE was not an integer!");
	let spec_file = unsafe { File::from_raw_fd(spec_fd) };
	let spec: Spec = serde_json::from_reader(&spec_file).expect("Unable to read spec file!");

	let linux_spec = spec.linux().as_ref().unwrap();

	debug!("generate clone-flags");
	let cloneflags = if let Some(namespaces) = &linux_spec.namespaces() {
		flags::generate_cloneflags(namespaces)
	} else {
		CloneFlags::empty()
	};

	debug!("set process as non-dumpable");
	prctl::set_dumpable(false).expect("Could not set process as non-dumpable!");

	// debug!("create child sync pipe");
	// let parent_child_sync = SocketPair::from(
	// 	socket::socketpair(
	// 		socket::AddressFamily::Unix,
	// 		socket::SockType::Stream,
	// 		None,
	// 		socket::SockFlag::SOCK_CLOEXEC,
	// 	)
	// 	.expect("Could not create parent-child socket pair for init pipe!"),
	// );

	// debug!("create grandchild sync pipe");
	// let parent_grandchild_sync = SocketPair::from(
	// 	socket::socketpair(
	// 		socket::AddressFamily::Unix,
	// 		socket::SockType::Stream,
	// 		None,
	// 		socket::SockFlag::SOCK_CLOEXEC,
	// 	)
	// 	.expect("Could not create parent-grandchild socket pair for init pipe!"),
	// );

	debug!("jump into init_stage");
	init_stage(SetupArgs {
		stage: InitStage::Parent,
		init_pipe: init_pipe.into_raw_fd(),
		config: InitConfig {
			spec,
			cloneflags,
			rootfs: rootfs_path,
			bundle_rootfs: bundle_rootfs_path,
			is_hermit_container,
		},
	});
}

fn clone_process(mut args: Box<CloneArgs>) -> nix::unistd::Pid {
	extern "C" fn callback(data: *mut CloneArgs) -> i32 {
		let cb: Box<CloneArgs> = unsafe { Box::from_raw(data) };
		(*cb.child_func)(cb.args) as i32
	}

	let res = unsafe {
		let combined = nix::sched::CloneFlags::CLONE_PARENT.bits() | libc::SIGCHLD;
		let ptr = args.stack.as_mut_ptr().add(args.stack.len() - 16);
		let ptr_aligned = ptr.offset(-((ptr as usize % 16) as isize));
		libc::clone(
			std::mem::transmute(callback as extern "C" fn(*mut CloneArgs) -> i32),
			ptr_aligned as *mut libc::c_void,
			combined,
			Box::into_raw(args) as *mut libc::c_void,
		)
	};

	nix::errno::Errno::result(res)
		.map(nix::unistd::Pid::from_raw)
		.expect("Could not clone parent process!")
}

fn init_stage(args: SetupArgs) -> isize {
	let linux_spec = args.config.spec.linux().as_ref().unwrap();
	match args.stage {
		// InitStage::Parent => {
		// 	debug!("enter init_stage parent");
		// 	// Setting the name is just for debugging purposes so it doesnt cause problems if it fails
		// 	let _ = prctl::set_name("runh:PARENT");
		// 	let child_pid = clone_process(Box::new(CloneArgs {
		// 		stack: [0; STACK_SIZE],
		// 		args: SetupArgs {
		// 			stage: InitStage::Child,
		// 			init_pipe: args.init_pipe,
		// 			parent_child_sync: args.parent_child_sync,
		// 			parent_grandchild_sync: args.parent_grandchild_sync,
		// 			config: args.config,
		// 		},
		// 		child_func: Box::new(init_stage),
		// 	}));
		// 	debug!("Created child with pid {}", child_pid);
		// 	debug!("Wait for synchronization with children!");

		// 	let mut pid_buffer = [0; 4];
		// 	let mut child_sync_pipe = unsafe { File::from_raw_fd(args.parent_child_sync.parent) };
		// 	debug!(
		// 		"Listening on fd {} for grandchild pid",
		// 		args.parent_child_sync.parent
		// 	);
		// 	child_sync_pipe
		// 		.read_exact(&mut pid_buffer)
		// 		.expect("could not synchronize with first child!");

		// 	let received_pid = i32::from_le_bytes(pid_buffer);
		// 	debug!("Received child PID: {}", received_pid);

		// 	debug!("send child PID to runh create");
		// 	let mut init_pipe = unsafe { File::from_raw_fd(RawFd::from(args.init_pipe)) };
		// 	init_pipe
		// 		.write(&pid_buffer)
		// 		.expect("Unable to write to init-pipe!");
		// 	return 0; // Exit parent
		// }
		InitStage::Parent => {
			debug!("Enter init_stage parent");
			// Setting the name is just for debugging purposes so it doesnt cause problems if it fails
			let _ = prctl::set_name("runh:PARENT");

			if let Some(namespaces) = &linux_spec.namespaces() {
				namespaces::join_namespaces(namespaces)
			}

			//TODO: Unshare user namespace if requested (needs additional clone)
			if args.config.cloneflags.contains(CloneFlags::CLONE_NEWUSER) {
				unimplemented!("User namespaces are currently not supported by runh!")
			}

			//TODO: Let parent setup uidmap/gidmap if a user namespace was joined

			nix::unistd::setresuid(Uid::from_raw(0), Uid::from_raw(0), Uid::from_raw(0))
				.expect("could not become root in user namespace!");

			// Unshare all other namespaces (except cgroup)
			debug!(
				"unshare namespaces with cloneflags {:?}",
				args.config.cloneflags
			);
			let mut flags = args.config.cloneflags;
			flags.remove(CloneFlags::CLONE_NEWCGROUP);
			nix::sched::unshare(flags).expect("could not unshare non-user namespaces!");

			// Fork again into new PID-Namespace and send PID to parent
			let child_pid: i32 = clone_process(Box::new(CloneArgs {
				stack: [0; STACK_SIZE],
				args: SetupArgs {
					stage: InitStage::Child,
					init_pipe: args.init_pipe,
					config: args.config,
				},
				child_func: Box::new(init_stage),
			}))
			.into();

			debug!("Send child PID to runh create");
			let mut init_pipe = unsafe { File::from_raw_fd(args.init_pipe) };
			let written_bytes = init_pipe
				.write(&child_pid.to_le_bytes())
				.expect("Unable to write to init-pipe!");
			debug!("Wrote {} bytes for child-PID", written_bytes);
			0 // Exit child process
		}
		InitStage::Child => {
			debug!("Enter init_stage child");
			let _ = prctl::set_name("runh:INIT");
			debug!("Welcome to the container! This is PID {}", Pid::this());

			// Set SID, UID, GID
			let _ = nix::unistd::setsid().expect("Could not set session ID");
			nix::unistd::setuid(Uid::from_raw(0)).expect("Could not set user ID");
			nix::unistd::setgid(Gid::from_raw(0)).expect("Could not set group ID");

			// TODO: Call setgroups if !is_rootless_euid && is_setgroup (?)

			// Unshare Cgroup namespace if requested to
			if args.config.cloneflags.contains(CloneFlags::CLONE_NEWCGROUP) {
				// TODO: Synchronize with runh create for cgroup setup
				nix::sched::unshare(CloneFlags::CLONE_NEWCGROUP)
					.expect("could not unshare cgroups namespace!");
			}

			// In runc's case, this is the point where control is transferred back to the go runtime
			debug!("Read config from spec file");
			let fifo_fd: i32 = env::var("RUNH_FIFOFD")
				.expect("No fifo fd given!")
				.parse()
				.expect("RUNH_FIFOFD was not an integer!");

			//Safe log_pipe_fd, so we can close it after setup is done.
			let log_pipe_fd: Option<RawFd> = if let Ok(log_fd) = std::env::var("RUNH_LOG_PIPE") {
				Some(
					log_fd
						.parse::<i32>()
						.expect("RUNH_LOG_PIPE was not an integer!"),
				)
			} else {
				warn!("RUNH_LOG_PIPE was not set for init-process, so no log forwarding will happen! Continuing anyway...");
				None
			};

			let mut console_fd = 0;

			if args
				.config
				.spec
				.process()
				.as_ref()
				.unwrap()
				.terminal()
				.unwrap_or(false)
			{
				console_fd = env::var("RUNH_CONSOLE")
					.expect("No console fd given!")
					.parse()
					.expect("RUNH_CONSOLE was not an integer!");
			}

			unsafe {
				libc::clearenv();
			}

			// Set environment variables found in the config
			if let Some(process) = &args.config.spec.process() {
				if let Some(env) = &process.env() {
					debug!("Load environment variables from config");
					for var in env {
						let (name, value) = var.split_once('=').unwrap_or_else(|| {
							panic!("Could not parse environment variable: {}", var)
						});
						if !name.is_empty() {
							std::env::set_var(name, value);
						}
					}
				}
			}

			//TODO: Create new session keyring if requested
			//TODO: Setup network and routing
			let mut setup_network = false;
			let mut network_namespace: Option<String> = None;
			for ns in args
				.config
				.spec
				.linux()
				.as_ref()
				.unwrap()
				.namespaces()
				.as_ref()
				.unwrap()
			{
				if ns.typ() == runtime::LinuxNamespaceType::Network {
					if ns.path().is_none() || ns.path().as_ref().unwrap().as_os_str().is_empty() {
						setup_network = true;
					} else {
						network_namespace =
							Some(ns.path().as_ref().unwrap().to_str().unwrap().to_string());
					}
				}
			}
			let tokio_runtime =
				tokio::runtime::Runtime::new().expect("Could not spawn new tokio runtime!");

			if setup_network {
				tokio_runtime
					.block_on(network::set_lo_up())
					.expect("Could not setup network lo interface!");
			}

			let rootfs_path = PathBuf::from(args.config.rootfs);
			let bundle_rootfs_path = PathBuf::from(args.config.bundle_rootfs);

			//Mount root file system
			rootfs::mount_rootfs(&args.config.spec, &rootfs_path);

			//Setup mounts and devices
			let setup_dev = if let Some(mounts) = args.config.spec.mounts() {
				mounts::configure_mounts(
					mounts,
					&rootfs_path,
					&bundle_rootfs_path,
					args.config.spec.linux().as_ref().unwrap().mount_label(),
				)
			} else {
				true
			};

			if setup_dev {
				devices::create_devices(linux_spec.devices(), &rootfs_path);
				devices::setup_ptmx(&rootfs_path);
				devices::setup_dev_symlinks(&rootfs_path);
			}

			if args.config.is_hermit_container {
				devices::mount_hermit_devices(&rootfs_path);
				devices::create_tun(
					&rootfs_path,
					Uid::from_raw(args.config.spec.process().as_ref().unwrap().user().uid()),
					Gid::from_raw(args.config.spec.process().as_ref().unwrap().user().gid()),
				);
			}

			//Run pre-start hooks
			debug!("Signalling parent to run pre-start hooks");
			let mut init_pipe = unsafe { File::from_raw_fd(args.init_pipe) };
			init_pipe
				.write_all(&[crate::consts::INIT_REQ_PRESTART_HOOKS])
				.expect("Unable to write to init-pipe!");

			let mut sig_buffer = [0u8];
			init_pipe
				.read_exact(&mut sig_buffer)
				.expect("Could not read from init pipe!");
			if sig_buffer[0] != crate::consts::CREATE_ACK_PRESTART_HOOKS {
				panic!(
					"Received invalid signal from runh create! Expected {:x}, got {:x}",
					crate::consts::CREATE_ACK_PRESTART_HOOKS,
					sig_buffer[0]
				);
			}

			let hermit_network_config = if args.config.is_hermit_container {
				match tokio_runtime.block_on(network::create_tap(network_namespace.clone())) {
					Ok(config) => {
						if config.did_init && network_namespace.is_some() {
							init_pipe
								.write_all(&[crate::consts::INIT_REQ_SAVE_NETWORK_SETUP])
								.expect("Unable to write to init-pipe!");

							let network_config_str = serde_json::to_string(&config)
								.expect("Could not serialize hermit network config!");

							debug!(
								"Write hermit network config {} (lenght {}) to init-pipe!",
								network_config_str,
								network_config_str.len()
							);
							init_pipe
								.write_all(&(network_config_str.len() as usize).to_le_bytes())
								.expect("Could not write hermit env path size to init pipe!");

							init_pipe
								.write_all(network_config_str.as_bytes())
								.expect("Could not write hermit env path to init pipe!");
						} else {
							init_pipe
								.write_all(&[crate::consts::INIT_REQ_SKIP_NETWORK_SETUP])
								.expect("Unable to write to init-pipe!");
						}
						let mut sig_buffer = [0u8];
						init_pipe
							.read_exact(&mut sig_buffer)
							.expect("Could not read from init pipe!");
						if sig_buffer[0] != crate::consts::CREATE_ACK_NETWORK_SETUP {
							panic!(
								"Received invalid signal from runh create! Expected {:x}, got {:x}",
								crate::consts::CREATE_ACK_NETWORK_SETUP,
								sig_buffer[0]
							);
						}
						Some(config)
					}
					Err(x) => {
						warn!("Hermit network setup could not be completed: {}", x);
						init_pipe
							.write_all(&[crate::consts::INIT_REQ_SKIP_NETWORK_SETUP])
							.expect("Unable to write to init-pipe!");
						let mut sig_buffer = [0u8];
						init_pipe
							.read_exact(&mut sig_buffer)
							.expect("Could not read from init pipe!");
						if sig_buffer[0] != crate::consts::CREATE_ACK_NETWORK_SETUP {
							panic!(
								"Received invalid signal from runh create! Expected {:x}, got {:x}",
								crate::consts::CREATE_ACK_NETWORK_SETUP,
								sig_buffer[0]
							);
						}
						None
					}
				}
			} else {
				None
			};

			nix::unistd::chdir(&rootfs_path).unwrap_or_else(|_| {
				panic!(
					"Could not change directory to rootfs path {:?}",
					rootfs_path
				)
			});

			//TODO: Run create hooks

			if args.config.cloneflags.contains(CloneFlags::CLONE_NEWNS) {
				rootfs::pivot_root(&rootfs_path);
			} else {
				nix::unistd::chroot(".").expect("Could not chroot into current directory!");
				nix::unistd::chdir("/").expect("Could not chdir to / after chroot!");
			}

			//TODO: re-open /dev/null in the container if any std-fd points to it

			let cwd = args.config.spec.process().as_ref().unwrap().cwd();
			if !cwd.as_os_str().is_empty() {
				mounts::create_all_dirs(&PathBuf::from(cwd));
			}

			//Setup console
			if args
				.config
				.spec
				.process()
				.as_ref()
				.unwrap()
				.terminal()
				.unwrap_or(false)
			{
				let console_socket = unsafe { File::from_raw_fd(console_fd) };

				let win_size = args
					.config
					.spec
					.process()
					.as_ref()
					.unwrap()
					.console_size()
					.as_ref()
					.map(|b| nix::pty::Winsize {
						ws_row: b.height() as u16,
						ws_col: b.width() as u16,
						ws_xpixel: 0,
						ws_ypixel: 0,
					});

				console::setup_console(console_socket, win_size.as_ref());
			}

			//Finalize rootfs
			if args.config.cloneflags.contains(CloneFlags::CLONE_NEWNS) {
				//TODO: Remount /dev as ro if requested

				if let Some(root) = args.config.spec.root() {
					if root.readonly().unwrap_or(false) {
						rootfs::set_rootfs_read_only();
					}
				}
				let _ = nix::sys::stat::umask(nix::sys::stat::Mode::from_bits(0o022).unwrap());
			}

			if let Some(hostname) = args.config.spec.hostname() {
				debug!("set hostname to {}", &hostname);
				nix::unistd::sethostname(hostname).expect("Could not set hostname!");
			}

			//TODO: Apply apparmor profile
			//TODO: Write sysctl keys
			if let Some(sysctl) = args.config.spec.linux().as_ref().unwrap().sysctl().as_ref() {
				for (key, value) in sysctl {
					let key_path = key.replace('.', "/");
					let full_path = PathBuf::from("/proc/sys").join(key_path);
					let mut sysctl_file = OpenOptions::new()
						.mode(0o644)
						.create(true)
						.write(true)
						.open(&full_path)
						.unwrap_or_else(|_| {
							panic!("Could not create sysctl entry at {:?}", full_path)
						});
					sysctl_file.write_all(value.as_bytes()).unwrap_or_else(|_| {
						panic!(
							"Could not write value {} to sysctl entry at {:?}",
							value, full_path
						)
					});
				}
			}

			//TODO: Manage readonly and mask paths

			// Set no_new_privileges
			if let Some(process) = &args.config.spec.process() {
				if process.no_new_privileges().unwrap_or(false) {
					debug!("set no_new_privileges");
					prctl::set_no_new_privs().expect("Could not set no_new_privs flag!");
				}
			}

			//TODO: Apply seccomp
			//TODO: Finalize Namespace
			// - Ensure all fd's are CLOEXEC
			// - Change to cwd
			// - Change user
			// - Apply capabilities

			//Verify the args[0] executable exists
			let exec_args = if args.config.is_hermit_container {
				let app = args
					.config
					.spec
					.process()
					.as_ref()
					.unwrap()
					.args()
					.as_ref()
					.unwrap()
					.get(0)
					.expect("Container spec does not contain any args!")
					.as_str();
				let app_root = PathBuf::from(app)
					.parent()
					.expect("App path does not have a parent!")
					.to_owned();
				let kernel_path = app_root.join("rusty-loader");
				let kernel = kernel_path.as_os_str().to_str().unwrap();
				let kvm: u32 = env::var("RUNH_KVM")
					.unwrap_or_else(|_| "0".to_string())
					.parse()
					.expect("RUNH_KVM was not an unsigned integer!");
				let micro_vm: u32 = env::var("RUNH_MICRO_VM")
					.unwrap_or_else(|_| "1".to_string())
					.parse()
					.expect("RUNH_MICRO_VM was not an unsigned integer!");
				hermit::get_qemu_args(
					kernel,
					app,
					&hermit_network_config,
					args.config
						.spec
						.process()
						.as_ref()
						.unwrap()
						.args()
						.as_ref()
						.unwrap(),
					micro_vm > 0,
					kvm > 0,
				)
			} else {
				args.config
					.spec
					.process()
					.as_ref()
					.unwrap()
					.args()
					.as_ref()
					.unwrap()
					.clone()
			};

			let exec_path_rel = PathBuf::from(
				exec_args
					.get(0)
					.expect("Container spec does not contain any args!"),
			);
			let exec_path_abs = paths::find_in_path(exec_path_rel, None)
				.expect("Could not determine location of args-executable!");

			info!("Found args-executable: {:?}", exec_path_abs);
			info!("Running command {}", exec_args.join(" "));

			//Tell runh create we are ready to execv
			init_pipe
				.write_all(&[crate::consts::INIT_READY_TO_EXECV])
				.expect("Unable to write to init-pipe!");

			info!("Runh init setup complete. Now waiting for signal to execv!");

			//Close log pipe. All log calls after this should fail due to the log file being closed.
			if let Some(log_pipe_fd) = log_pipe_fd {
				debug!("Closing log pipe...");
				nix::unistd::close(log_pipe_fd).expect("Could not close log pipe fd!");
			}

			let mut exec_fifo = OpenOptions::new()
				.custom_flags(libc::O_CLOEXEC)
				.read(false)
				.write(true)
				.open(format!("/proc/self/fd/{}", fifo_fd))
				.expect("Could not open exec fifo!");

			write!(exec_fifo, "\0").expect("Could not write to exec fifo!");
			drop(exec_fifo);

			let mut cmd = std::process::Command::new(exec_path_abs);
			cmd.arg0(exec_args.get(0).unwrap());
			if exec_args.len() > 1 {
				cmd.args(exec_args.get(1..).unwrap());
			}
			cmd.envs(std::env::vars());
			let error = cmd.exec();

			//This point should not be reached on successful exec
			panic!("exec failed with error {}", error);
		}
	}
}
