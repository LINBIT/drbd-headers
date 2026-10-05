/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause) */
/* Do not edit directly, auto-generated from: */
/*	drbd2.yaml */
/* YNL-GEN userspace header */
/* To regenerate run: tools/net/ynl/ynl-regen.sh */

#ifndef _LINUX_DRBD2_GEN_USERSPACE_H
#define _LINUX_DRBD2_GEN_USERSPACE_H

#include <linux/types.h>
#include "libgenl.h"

#include <uapi/linux/drbd2.h>

/* Nested type policies */
extern const struct nla_policy drbd2_address_nl_policy[DRBD2_A_ADDRESS_IPV6 + 1];
extern const struct nla_policy drbd2_connect_parms_nl_policy[DRBD2_A_CONNECT_PARMS_DISCARD_MY_DATA + 1];
extern const struct nla_policy drbd2_connection_nl_policy[DRBD2_A_CONNECTION_PATH + 1];
extern const struct nla_policy drbd2_connection_info_nl_policy[DRBD2_A_CONNECTION_INFO_ROLE + 1];
extern const struct nla_policy drbd2_connection_statistics_nl_policy[DRBD2_A_CONNECTION_STATISTICS_RS_IN_FLIGHT + 1];
extern const struct nla_policy drbd2_context_nl_policy[DRBD2_A_CONTEXT_PEER_ADDRESS + 1];
extern const struct nla_policy drbd2_detach_parms_nl_policy[DRBD2_A_DETACH_PARMS_INTENTIONAL_DISKLESS_DETACH + 1];
extern const struct nla_policy drbd2_device_nl_policy[DRBD2_A_DEVICE_DEVICE_CONF + 1];
extern const struct nla_policy drbd2_device_conf_nl_policy[DRBD2_A_DEVICE_CONF_DISCARD_GRANULARITY + 1];
extern const struct nla_policy drbd2_device_info_nl_policy[DRBD2_A_DEVICE_INFO_BACKING_DEV_PATH + 1];
extern const struct nla_policy drbd2_device_statistics_nl_policy[DRBD2_A_DEVICE_STATISTICS_HISTORY_UUIDS + 1];
extern const struct nla_policy drbd2_disconnect_parms_nl_policy[DRBD2_A_DISCONNECT_PARMS_FORCE + 1];
extern const struct nla_policy drbd2_disk_conf_nl_policy[DRBD2_A_DISK_CONF_BITMAP + 1];
extern const struct nla_policy drbd2_helper_info_nl_policy[DRBD2_A_HELPER_INFO_PHASE + 1];
extern const struct nla_policy drbd2_invalidate_parms_nl_policy[DRBD2_A_INVALIDATE_PARMS_RESET_BITMAP + 1];
extern const struct nla_policy drbd2_invalidate_peer_parms_nl_policy[DRBD2_A_INVALIDATE_PEER_PARMS_RESET_BITMAP + 1];
extern const struct nla_policy drbd2_net_conf_nl_policy[DRBD2_A_NET_CONF_RDMA_CTRL_SNDBUF_SIZE + 1];
extern const struct nla_policy drbd2_new_current_uuid_parms_nl_policy[DRBD2_A_NEW_CURRENT_UUID_PARMS_FORCE_RESYNC + 1];
extern const struct nla_policy drbd2_path_nl_policy[DRBD2_A_PATH_INFO + 1];
extern const struct nla_policy drbd2_path_info_nl_policy[DRBD2_A_PATH_INFO_ESTABLISHED + 1];
extern const struct nla_policy drbd2_peer_device_nl_policy[DRBD2_A_PEER_DEVICE_PEER_DEVICE_CONF + 1];
extern const struct nla_policy drbd2_peer_device_conf_nl_policy[DRBD2_A_PEER_DEVICE_CONF_PEER_TIEBREAKER + 1];
extern const struct nla_policy drbd2_peer_device_info_nl_policy[DRBD2_A_PEER_DEVICE_INFO_RESYNC_SUSP_MAX_PARALLEL + 1];
extern const struct nla_policy drbd2_peer_device_statistics_nl_policy[DRBD2_A_PEER_DEVICE_STATISTICS_UUID_FLAGS + 1];
extern const struct nla_policy drbd2_rename_parms_nl_policy[DRBD2_A_RENAME_PARMS_NEW_NAME + 1];
extern const struct nla_policy drbd2_resize_parms_nl_policy[DRBD2_A_RESIZE_PARMS_AL_STRIPE_SIZE + 1];
extern const struct nla_policy drbd2_resource_nl_policy[DRBD2_A_RESOURCE_RESOURCE_OPTS + 1];
extern const struct nla_policy drbd2_resource_info_nl_policy[DRBD2_A_RESOURCE_INFO_FAIL_IO + 1];
extern const struct nla_policy drbd2_resource_opts_nl_policy[DRBD2_A_RESOURCE_OPTS_EXPLICIT_DRBD8_COMPAT + 1];
extern const struct nla_policy drbd2_resource_statistics_nl_policy[DRBD2_A_RESOURCE_STATISTICS_WRITE_ORDERING + 1];
extern const struct nla_policy drbd2_set_role_parms_nl_policy[DRBD2_A_SET_ROLE_PARMS_FORCE + 1];
extern const struct nla_policy drbd2_start_ov_parms_nl_policy[DRBD2_A_START_OV_PARMS_STOP_SECTOR + 1];
extern const struct nla_policy drbd2_suspend_io_parms_nl_policy[DRBD2_A_SUSPEND_IO_PARMS_BDEV_FREEZE + 1];

#define DRBD2_TLA_NL_POLICY_LEN (DRBD2_A_PATH + 1)
extern const struct nla_policy drbd2_tla_nl_policy[DRBD2_TLA_NL_POLICY_LEN];

#endif /* _LINUX_DRBD2_GEN_USERSPACE_H */
