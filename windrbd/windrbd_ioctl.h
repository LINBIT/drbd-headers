#ifndef WINDRBD_IOCTL_H
#define WINDRBD_IOCTL_H

#ifdef __CYGWIN__

#include <sys/types.h>			/* for int64_t */

	/* Windows user space (Cygwin, for drbd-utils) */

#ifndef GENL_NAMSIZ
#define GENL_NAMSIZ 16
#endif

#else

	/* Windows kernel space (WinDRBD kernel driver with Linux emulation) */

#include <linux/netlink.h>
#endif

/* For compiling this for drbd-utils when there are no Windows headers
 * installed, we need this (taken from ReactOS): Hopefully this never
 * changes.
 */

#ifndef CTL_CODE
#define CTL_CODE( DeviceType, Function, Method, Access ) (                 \
    ((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method) \
)
#endif

/* Mostly only used for sending ioctl's. User is a device object
 * accessible by anyone. This allows us for drbdadm status as
 * a non-Administrator user.
 */

#define WINDRBD_ROOT_DEVICE_NAME "windrbd_control"
#define WINDRBD_USER_DEVICE_NAME "windrbd_control_user"

/* TODO: are these used by someone else? Doc states that <= 0x8000
 * is reserved by Microsoft, but it does not state how to obtain
 * such a number. Plus the WINDRBD_DEVICEs appear as FILE_DEVICE_DISK.
 */

#define WINDRBD_DEVICE_TYPE 0xab26
#define WINDRBD_ROOT_DEVICE_TYPE 0xab27

#define IOCTL_WINDRBD_ROOT_IS_WINDRBD_ROOT_DEVICE CTL_CODE(WINDRBD_ROOT_DEVICE_TYPE, 1, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_WINDRBD_IS_WINDRBD_DEVICE CTL_CODE(WINDRBD_DEVICE_TYPE, 1, METHOD_BUFFERED, FILE_ANY_ACCESS)

enum fault_injection_location {
	INVALID_FAULT_LOCATION = -1,
	ON_ALL_REQUESTS_ON_REQUEST = 0,
	ON_ALL_REQUESTS_ON_COMPLETION,
	ON_META_DEVICE_ON_REQUEST,
	ON_META_DEVICE_ON_COMPLETION,
	ON_BACKING_DEVICE_ON_REQUEST,
	ON_BACKING_DEVICE_ON_COMPLETION,
	AFTER_LAST_FAULT_LOCATION
};

struct windrbd_ioctl_fault_injection {
		/* Inject faults after this number requests (and keep
		 * injecting faults). If 0, inject now. If < 0 do not
		 * inject faults (any more, this is the default).
		 */
	int after;
	enum fault_injection_location where;
};

#define IOCTL_WINDRBD_ROOT_INJECT_FAULTS CTL_CODE(WINDRBD_ROOT_DEVICE_TYPE, 2, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_WINDRBD_INJECT_FAULTS CTL_CODE(WINDRBD_DEVICE_TYPE, 2, METHOD_BUFFERED, FILE_ANY_ACCESS)

struct windrbd_ioctl_genl_portid {
	uint32_t portid;
};

struct windrbd_ioctl_genl_portid_and_multicast_group {
	uint32_t portid;
        char name[GENL_NAMSIZ];
};

/* Send netlink packet(s) to kernel.
 *
 * Input buffer: the netlink packet.
 * Output buffer: none.
 *
 * Call multiple times if there are more than one netlink request.
 * Return packet(s) to be fetched by receive nl packet ioctl().
 */

#define IOCTL_WINDRBD_ROOT_SEND_NL_PACKET CTL_CODE(WINDRBD_ROOT_DEVICE_TYPE, 3, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* Receive netlink packet(s) from kernel.
 *
 * Input buffer: the port id (getpid()) in a struct windrbd_ioctl_genl_portid
 * Output buffer: the netlink reply packet(s).
 *
 * Call multiple times if there are more reply packets than the output buffer
 * can hold. Output buffer should hold at least NLMSG_GOODSIZE bytes,
 * the actual size is returned by the lpBytesReturned parameter to
 * DeviceIoControl().
 *
 */

#define IOCTL_WINDRBD_ROOT_RECEIVE_NL_PACKET CTL_CODE(WINDRBD_ROOT_DEVICE_TYPE, 4, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* Add port ID to multicast group.
 *
 * Input buffer: the port id (getpid()) and name of the multicast group
 * 		 in a struct windrbd_ioctl_genl_portid_and_multicast_group
 * Output buffer: none.
 *
 * Adds the portid to multicast group specified in input buffer. As a
 * consequence, everything DRBD sends to that multicast group can be
 * received by the RECEIVE_NL_PACKET ioctl.
 *
 * Currently DRBD only uses the 'events' multicast group, however this
 * may change in the future. Note that WinDRBD has no notion of netlink
 * families since there is only DRBD to support.
 */

#define IOCTL_WINDRBD_ROOT_JOIN_MC_GROUP CTL_CODE(WINDRBD_ROOT_DEVICE_TYPE, 5, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* Something > 0x10, this is the value current kernels (4.1x) use.
 * Do not change.
 */

#define WINDRBD_NETLINK_FAMILY_ID	28

struct windrbd_usermode_helper {
		/* ID given by kernel to find return value request later. */
	int id;

		/* The total size of the helper struct including all data
		 * and this header information. If not enough space
		 * is provided this member contains the space needed
		 */
	size_t total_size;

		/* Since we cannot map a NULL pointer over the ioctl()
		 * interface, we store the number of the args (and env)
		 * in seperate arguments here.
		 */
	int argc;
	int envc;

		/* Data:
		 * cmd<0>arg1<0>arg2<0>...argn<0>env1<0>env2<0> ... envn<0>
		 * the above members determine how many args/how many envs.
		 */
	char data[];
};

struct windrbd_usermode_helper_return_value {
	int id;

		/* The return value of the handler. As far as I can tell
		 * nothing else is transferred to the kernel (no stdout/
		 * stderr).
		 */
	int retval;
};

/* This is for calling usermode helpers.
 *
 * Input: None
 * Output: a struct windrbd_usermode_helper with variable data member.
 *
 * Linux has a built-in call_usermode_helper() function which we need
 * to emulate. With this ioctl a usermode daemon retrieves commands
 * (with args and env) to run from the kernel (there may be 0-n
 * daemons running). Daemons return the return value of the handler
 * in a IOCTL_WINDRBD_ROOT_SEND_USERMODE_HELPER_RETURN_VALUE later.
 * There is a timeout for sending this (also to handle the case
 * where no daemon is running). Linux DRBD also has this timeout
 * in order to not get stuck on hanging handlers.
 *
 * The size of the output buffer should be at least 8192 bytes, in
 * case the ioctl() returns ERROR_INSUFFICIENT_BUFFER retry
 * with a bigger buffer.
 */

#define IOCTL_WINDRBD_ROOT_RECEIVE_USERMODE_HELPER CTL_CODE(WINDRBD_ROOT_DEVICE_TYPE, 6, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* This is for returning the exit status of usermode helpers to the kernel.
 * Input: a windrbd_usermode_helper_return_value containing id and retvalue.
 * Output: none
 *
 * See IOCTL_WINDRBD_ROOT_RECEIVE_USERMODE_HELPER ioctl for more details.
 */

#define IOCTL_WINDRBD_ROOT_SEND_USERMODE_HELPER_RETURN_VALUE CTL_CODE(WINDRBD_ROOT_DEVICE_TYPE, 7, METHOD_BUFFERED, FILE_ANY_ACCESS)

struct windrbd_minor_mount_point {
	int minor;
	wchar_t mount_point[1];
};

/* Set a mount point for a DRBD minor.
 * Input: a struct windrbd_minor_mount_point
 * Output: none
 *
 * Sets a Windows NT mount point for DRBD minor. This is usually done right
 * after creating the minor, but it can be changed later. The mount point
 * can be a drive letter (in the form X:) or an empty NTFS directory
 * (right now, only drive letter is implemented). The mount point is
 * specified in 16-bit Unicode (UTF-16) in order to allow for directory
 * paths containing non-latin characters later (however drbd.conf does
 * not support this and probably never will, so one has to do that manually).
 *
 * Please make sure that mount_point field is zero-terminated (using
 * a 16-bit 0 value).
 *
 * The mount/umount process itself happens internally on becoming primary/
 * secondary later, so this has to be done before becoming primary. If
 * the mount point is changed at any point in time, we requre a drbdadm
 * secondary / drbdadm primary to take changes effect.
 */

#define IOCTL_WINDRBD_ROOT_SET_MOUNT_POINT_FOR_MINOR CTL_CODE(WINDRBD_ROOT_DEVICE_TYPE, 8, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* Return DRBD version.
 * Input: none
 * Output: A (char*) buffer of at least 256 bytes.
 *
 * Returns the DRBD REL_VERSION string that this WinDRBD release is
 * based on.
 */

#define IOCTL_WINDRBD_ROOT_GET_DRBD_VERSION CTL_CODE(WINDRBD_ROOT_DEVICE_TYPE, 9, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* Return WinDRBD version.
 * Input: none
 * Output: A (char*) buffer of at least 256 bytes.
 *
 * Returns the WinDRBD string as reported by git describe --tags
 */

#define IOCTL_WINDRBD_ROOT_GET_WINDRBD_VERSION CTL_CODE(WINDRBD_ROOT_DEVICE_TYPE, 10, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* Cause WinDRBD to dump allocated memory regions.
 * Input: none
 * Output: none
 *
 * WinDRBD will printk all currently allocated memory (only if compiled
 * with kmalloc debug support).
 */

#define IOCTL_WINDRBD_ROOT_DUMP_ALLOCATED_MEMORY CTL_CODE(WINDRBD_ROOT_DEVICE_TYPE, 11, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* Cause WinDRBD to run DRBD URI parser test
 * Input: Test name and parameters (as a char*), currently none defined.
 * Output: none
 *
 * WinDRBD will printk results from the parser test.
 */

#define IOCTL_WINDRBD_ROOT_RUN_TEST CTL_CODE(WINDRBD_ROOT_DEVICE_TYPE, 12, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* Set syslog IP
 * Input: The syslog IP (must be v4) as a char*
 * Output: none
 *
 * Direct network printk's to this IP address.
 */

#define IOCTL_WINDRBD_ROOT_SET_SYSLOG_IP CTL_CODE(WINDRBD_ROOT_DEVICE_TYPE, 13, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* Create resource from URL
 * Input: The DRBD URL (see documentation on boot device) as a char*
 * Output: none
 *
 * Create a DRBD resource from an WinDRBD URL.
 */

#define IOCTL_WINDRBD_ROOT_CREATE_RESOURCE_FROM_URL CTL_CODE(WINDRBD_ROOT_DEVICE_TYPE, 14, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* Set the WinDRBD config key
 * Input: The config key as a hex string
 * Output: none
 *
 * Sets the key to lock writable DRBD commands
 */

#define IOCTL_WINDRBD_ROOT_SET_CONFIG_KEY CTL_CODE(WINDRBD_ROOT_DEVICE_TYPE, 15, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* Set the event log log level
 * Input: A signed 32-bit value (0=emerg, 1=alert, ...)
 * Output: none
 *
 * Sets the threshold value for messages that go into the Windows event log.
 */

#define IOCTL_WINDRBD_ROOT_SET_EVENT_LOG_LEVEL CTL_CODE(WINDRBD_ROOT_DEVICE_TYPE, 16, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* Report if config key is set (and required for manipulating resources)
 * Input: none
 * Output: an int: 1 .. system is locked 0 .. system is not locked
 *
 * Reports if config key is set
 */

#define IOCTL_WINDRBD_ROOT_GET_LOCK_DOWN_STATE CTL_CODE(WINDRBD_ROOT_DEVICE_TYPE, 17, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* Set WinDRBD shutdown flag.
 * Input: 1 - signal WinDRBD that it will be unloaded soon
 *        0 - cancel the above
 * Output: none
 *
 * Set WinDRBD shutdown flag. Will cause drbdsetup events2 to terminate.
 * Also all further drbdadm commands will fail.
 */

#define IOCTL_WINDRBD_ROOT_SET_SHUTDOWN_FLAG CTL_CODE(WINDRBD_ROOT_DEVICE_TYPE, 18, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* Check if there is a netlink packet without consuming it.
 *
 * Input buffer: the port id (getpid()) in a struct windrbd_ioctl_genl_portid
 * Output buffer: a 32 bit flag: 0 - no netlink packets 1 - there are netlink
 *                packets.
 */

#define IOCTL_WINDRBD_ROOT_ARE_THERE_NL_PACKETS CTL_CODE(WINDRBD_ROOT_DEVICE_TYPE, 19, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* Lock or unlock driver in memory
 * Input: 0 - Set AddDevice to NULL (if otherwise unused) driver can be unloaded
 *        1 - Set AddDevice to valid AddDevice function, driver cannot be unloaded
 * Output: none
 *
 * Controls whether WinDRBD is reacting to new devices (such as the bus device)
 * This allows to remove the bus driver and install it again without having
 * to unload the driver or reboot the system.
 */

#define IOCTL_WINDRBD_ROOT_SET_DRIVER_LOCKED CTL_CODE(WINDRBD_ROOT_DEVICE_TYPE, 20, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* Suspend/Resume I/O for a minor on the WinDRBD level (outside DRBD)
 *
 * Input: minor - the DRBD minor for which to suspend I/O for
 * Output: none
 *
 * When an application busy writes a block it may happen that
 * syncing never finished. In that case, set this suspend-io
 * flag, wait for sync to finish and then clear the suspend-io
 * flag again. Note that this is different from DRBD's suspend-io
 * command.
 */

#define IOCTL_WINDRBD_ROOT_SET_IO_SUSPENDED_FOR_MINOR CTL_CODE(WINDRBD_ROOT_DEVICE_TYPE, 21, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WINDRBD_ROOT_CLEAR_IO_SUSPENDED_FOR_MINOR CTL_CODE(WINDRBD_ROOT_DEVICE_TYPE, 22, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* Check if DRBD implements a certain command on the netlink layer
 *
 * Input: cmd (as an 32-bit int) to query
 * Output: 0 - does not implement command, 1 - implements command
 *
 * Newer drbd-utils query the netlink family of the Linux
 * kernel for known commands. We don't implement a full
 * netlink replacement but still want to query the kernel
 * for commands it knows. Therefore we introduced this ioctl
 * which checks if a certain command is known.
 */

#define IOCTL_WINDRBD_ROOT_DRBD_OP_IS_KNOWN CTL_CODE(WINDRBD_ROOT_DEVICE_TYPE, 23, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* Check if the WinDRBD virtual bus device is working correctly
 *
 * Input: none
 * Output: 0 - does NOT work correctly 1 - works as expected
 *
 * Sometimes the WinDRBD bus device does not work correctly after
 * a new install. The reason for that is yet unknown but we know
 * how to fix it. In order to allow the installer to apply the fix
 * we need a possibility to check if the bus device works as expected.
 */

#define IOCTL_WINDRBD_ROOT_BUS_DEVICE_IS_WORKING CTL_CODE(WINDRBD_ROOT_DEVICE_TYPE, 24, METHOD_BUFFERED, FILE_ANY_ACCESS)

#endif
