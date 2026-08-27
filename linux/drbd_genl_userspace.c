// SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause)
/* Do not edit directly, auto-generated from: */
/*	drbd_genl_ynl.yaml */
/* YNL-GEN userspace source */
/* To regenerate run: tools/net/ynl/ynl-regen.sh */

#include "drbd_genl_userspace.h"
#include "libgenl.h"
#include <string.h>
#include <stdio.h>
#include <errno.h>

/* Nested type policies */
const struct nla_policy drbd_connect_parms_nl_policy[DRBD_A_CONNECT_PARMS_DISCARD_MY_DATA + 1] = {
	[DRBD_A_CONNECT_PARMS_TENTATIVE] = { .type = NLA_U8, },
	[DRBD_A_CONNECT_PARMS_DISCARD_MY_DATA] = { .type = NLA_U8, },
};

const struct nla_policy drbd_connection_info_nl_policy[DRBD_A_CONNECTION_INFO_CONN_ROLE + 1] = {
	[DRBD_A_CONNECTION_INFO_CONN_CONNECTION_STATE] = { .type = NLA_U32, },
	[DRBD_A_CONNECTION_INFO_CONN_ROLE] = { .type = NLA_U32, },
};

const struct nla_policy drbd_connection_statistics_nl_policy[DRBD_A_CONNECTION_STATISTICS_RS_IN_FLIGHT + 1] = {
	[DRBD_A_CONNECTION_STATISTICS_CONN_CONGESTED] = { .type = NLA_U8, },
	[DRBD_A_CONNECTION_STATISTICS_AP_IN_FLIGHT] = { .type = NLA_U64, },
	[DRBD_A_CONNECTION_STATISTICS_RS_IN_FLIGHT] = { .type = NLA_U64, },
};

const struct nla_policy drbd_detach_parms_nl_policy[DRBD_A_DETACH_PARMS_INTENTIONAL_DISKLESS_DETACH + 1] = {
	[DRBD_A_DETACH_PARMS_FORCE_DETACH] = { .type = NLA_U8, },
	[DRBD_A_DETACH_PARMS_INTENTIONAL_DISKLESS_DETACH] = { .type = NLA_U8, },
};

const struct nla_policy drbd_device_conf_nl_policy[DRBD_A_DEVICE_CONF_DISCARD_GRANULARITY + 1] = {
	[DRBD_A_DEVICE_CONF_MAX_BIO_SIZE] = { .type = NLA_U32, },
	[DRBD_A_DEVICE_CONF_INTENTIONAL_DISKLESS] = { .type = NLA_U8, },
	[DRBD_A_DEVICE_CONF_BLOCK_SIZE] = { .type = NLA_U32, },
	[DRBD_A_DEVICE_CONF_DISCARD_GRANULARITY] = { .type = NLA_U32, },
};

const struct nla_policy drbd_device_info_nl_policy[DRBD_A_DEVICE_INFO_DEV_IS_OPEN + 1] = {
	[DRBD_A_DEVICE_INFO_DEV_DISK_STATE] = { .type = NLA_U32, },
	[DRBD_A_DEVICE_INFO_IS_INTENTIONAL_DISKLESS] = { .type = NLA_U8, },
	[DRBD_A_DEVICE_INFO_DEV_HAS_QUORUM] = { .type = NLA_U8, },
	[DRBD_A_DEVICE_INFO_DEV_IS_OPEN] = { .type = NLA_U8, },
	[DRBD_A_DEVICE_INFO_BACKING_DEV_PATH] = { .type = NLA_NUL_STRING, .len = 128, },
};

const struct nla_policy drbd_device_statistics_nl_policy[DRBD_A_DEVICE_STATISTICS_HISTORY_UUIDS + 1] = {
	[DRBD_A_DEVICE_STATISTICS_DEV_SIZE] = { .type = NLA_U64, },
	[DRBD_A_DEVICE_STATISTICS_DEV_READ] = { .type = NLA_U64, },
	[DRBD_A_DEVICE_STATISTICS_DEV_WRITE] = { .type = NLA_U64, },
	[DRBD_A_DEVICE_STATISTICS_DEV_AL_WRITES] = { .type = NLA_U64, },
	[DRBD_A_DEVICE_STATISTICS_DEV_BM_WRITES] = { .type = NLA_U64, },
	[DRBD_A_DEVICE_STATISTICS_DEV_UPPER_PENDING] = { .type = NLA_U32, },
	[DRBD_A_DEVICE_STATISTICS_DEV_LOWER_PENDING] = { .type = NLA_U32, },
	[DRBD_A_DEVICE_STATISTICS_DEV_UPPER_BLOCKED] = { .type = NLA_U8, },
	[DRBD_A_DEVICE_STATISTICS_DEV_LOWER_BLOCKED] = { .type = NLA_U8, },
	[DRBD_A_DEVICE_STATISTICS_DEV_AL_SUSPENDED] = { .type = NLA_U8, },
	[DRBD_A_DEVICE_STATISTICS_DEV_EXPOSED_DATA_UUID] = { .type = NLA_U64, },
	[DRBD_A_DEVICE_STATISTICS_DEV_CURRENT_UUID] = { .type = NLA_U64, },
	[DRBD_A_DEVICE_STATISTICS_DEV_DISK_FLAGS] = { .type = NLA_U32, },
	[DRBD_A_DEVICE_STATISTICS_HISTORY_UUIDS] = NLA_POLICY_MAX_LEN(HISTORY_UUIDS_SIZE),
};

const struct nla_policy drbd_disconnect_parms_nl_policy[DRBD_A_DISCONNECT_PARMS_FORCE_DISCONNECT + 1] = {
	[DRBD_A_DISCONNECT_PARMS_FORCE_DISCONNECT] = { .type = NLA_U8, },
};

const struct nla_policy drbd_disk_conf_nl_policy[DRBD_A_DISK_CONF_D_BITMAP + 1] = {
	[DRBD_A_DISK_CONF_BACKING_DEV] = { .type = NLA_NUL_STRING, .len = 128, },
	[DRBD_A_DISK_CONF_META_DEV] = { .type = NLA_NUL_STRING, .len = 128, },
	[DRBD_A_DISK_CONF_META_DEV_IDX] = { .type = NLA_S32, },
	[DRBD_A_DISK_CONF_DISK_SIZE] = { .type = NLA_U64, },
	[DRBD_A_DISK_CONF_ON_IO_ERROR] = { .type = NLA_U32, },
	[DRBD_A_DISK_CONF_RESYNC_AFTER] = { .type = NLA_S32, },
	[DRBD_A_DISK_CONF_AL_EXTENTS] = { .type = NLA_U32, },
	[DRBD_A_DISK_CONF_DISK_BARRIER] = { .type = NLA_U8, },
	[DRBD_A_DISK_CONF_DISK_FLUSHES] = { .type = NLA_U8, },
	[DRBD_A_DISK_CONF_DISK_DRAIN] = { .type = NLA_U8, },
	[DRBD_A_DISK_CONF_MD_FLUSHES] = { .type = NLA_U8, },
	[DRBD_A_DISK_CONF_DISK_TIMEOUT] = { .type = NLA_U32, },
	[DRBD_A_DISK_CONF_READ_BALANCING] = { .type = NLA_U32, },
	[DRBD_A_DISK_CONF_UNPLUG_WATERMARK] = { .type = NLA_U32, },
	[DRBD_A_DISK_CONF_RS_DISCARD_GRANULARITY] = { .type = NLA_U32, },
	[DRBD_A_DISK_CONF_AL_UPDATES] = { .type = NLA_U8, },
	[DRBD_A_DISK_CONF_DISCARD_ZEROES_IF_ALIGNED] = { .type = NLA_U8, },
	[DRBD_A_DISK_CONF_DISABLE_WRITE_SAME] = { .type = NLA_U8, },
	[DRBD_A_DISK_CONF_D_BITMAP] = { .type = NLA_U8, },
};

const struct nla_policy drbd_drbd_cfg_context_nl_policy[DRBD_A_DRBD_CFG_CONTEXT_CTX_PEER_NODE_ID + 1] = {
	[DRBD_A_DRBD_CFG_CONTEXT_CTX_PEER_NODE_ID] = { .type = NLA_U32, },
	[DRBD_A_DRBD_CFG_CONTEXT_CTX_VOLUME] = { .type = NLA_U32, },
	[DRBD_A_DRBD_CFG_CONTEXT_CTX_RESOURCE_NAME] = { .type = NLA_NUL_STRING, .len = 128, },
	[DRBD_A_DRBD_CFG_CONTEXT_CTX_MY_ADDR] = NLA_POLICY_MAX_LEN(128),
	[DRBD_A_DRBD_CFG_CONTEXT_CTX_PEER_ADDR] = NLA_POLICY_MAX_LEN(128),
	[DRBD_A_DRBD_CFG_CONTEXT_CTX_CONN_NAME] = { .type = NLA_NUL_STRING, .len = SHARED_SECRET_MAX, },
};

const struct nla_policy drbd_drbd_cfg_reply_nl_policy[DRBD_A_DRBD_CFG_REPLY_INFO_TEXT + 1] = {
	[DRBD_A_DRBD_CFG_REPLY_INFO_TEXT] = { .type = NLA_NUL_STRING, },
};

const struct nla_policy drbd_drbd_helper_info_nl_policy[DRBD_A_DRBD_HELPER_INFO_HELPER_STATUS + 1] = {
	[DRBD_A_DRBD_HELPER_INFO_HELPER_NAME] = { .type = NLA_NUL_STRING, .len = 32, },
	[DRBD_A_DRBD_HELPER_INFO_HELPER_STATUS] = { .type = NLA_U32, },
};

const struct nla_policy drbd_drbd_notification_header_nl_policy[DRBD_A_DRBD_NOTIFICATION_HEADER_NH_TYPE + 1] = {
	[DRBD_A_DRBD_NOTIFICATION_HEADER_NH_TYPE] = { .type = NLA_U32, },
};

const struct nla_policy drbd_drbd_path_info_nl_policy[DRBD_A_DRBD_PATH_INFO_PATH_ESTABLISHED + 1] = {
	[DRBD_A_DRBD_PATH_INFO_PATH_ESTABLISHED] = { .type = NLA_U8, },
};

const struct nla_policy drbd_forget_peer_parms_nl_policy[DRBD_A_FORGET_PEER_PARMS_FORGET_PEER_NODE_ID + 1] = {
	[DRBD_A_FORGET_PEER_PARMS_FORGET_PEER_NODE_ID] = { .type = NLA_S32, },
};

const struct nla_policy drbd_invalidate_parms_nl_policy[DRBD_A_INVALIDATE_PARMS_RESET_BITMAP + 1] = {
	[DRBD_A_INVALIDATE_PARMS_SYNC_FROM_PEER_NODE_ID] = { .type = NLA_S32, },
	[DRBD_A_INVALIDATE_PARMS_RESET_BITMAP] = { .type = NLA_U8, },
};

const struct nla_policy drbd_invalidate_peer_parms_nl_policy[DRBD_A_INVALIDATE_PEER_PARMS_P_RESET_BITMAP + 1] = {
	[DRBD_A_INVALIDATE_PEER_PARMS_P_RESET_BITMAP] = { .type = NLA_U8, },
};

const struct nla_policy drbd_net_conf_nl_policy[DRBD_A_NET_CONF_RDMA_CTRL_SNDBUF_SIZE + 1] = {
	[DRBD_A_NET_CONF_SHARED_SECRET] = { .type = NLA_NUL_STRING, .len = SHARED_SECRET_MAX, },
	[DRBD_A_NET_CONF_CRAM_HMAC_ALG] = { .type = NLA_NUL_STRING, .len = SHARED_SECRET_MAX, },
	[DRBD_A_NET_CONF_INTEGRITY_ALG] = { .type = NLA_NUL_STRING, .len = SHARED_SECRET_MAX, },
	[DRBD_A_NET_CONF_VERIFY_ALG] = { .type = NLA_NUL_STRING, .len = SHARED_SECRET_MAX, },
	[DRBD_A_NET_CONF_CSUMS_ALG] = { .type = NLA_NUL_STRING, .len = SHARED_SECRET_MAX, },
	[DRBD_A_NET_CONF_WIRE_PROTOCOL] = { .type = NLA_U32, },
	[DRBD_A_NET_CONF_CONNECT_INT] = { .type = NLA_U32, },
	[DRBD_A_NET_CONF_TIMEOUT] = { .type = NLA_U32, },
	[DRBD_A_NET_CONF_PING_INT] = { .type = NLA_U32, },
	[DRBD_A_NET_CONF_PING_TIMEO] = { .type = NLA_U32, },
	[DRBD_A_NET_CONF_SNDBUF_SIZE] = { .type = NLA_U32, },
	[DRBD_A_NET_CONF_RCVBUF_SIZE] = { .type = NLA_U32, },
	[DRBD_A_NET_CONF_KO_COUNT] = { .type = NLA_U32, },
	[DRBD_A_NET_CONF_MAX_EPOCH_SIZE] = { .type = NLA_U32, },
	[DRBD_A_NET_CONF_AFTER_SB_0P] = { .type = NLA_U32, },
	[DRBD_A_NET_CONF_AFTER_SB_1P] = { .type = NLA_U32, },
	[DRBD_A_NET_CONF_AFTER_SB_2P] = { .type = NLA_U32, },
	[DRBD_A_NET_CONF_RR_CONFLICT] = { .type = NLA_U32, },
	[DRBD_A_NET_CONF_ON_CONGESTION] = { .type = NLA_U32, },
	[DRBD_A_NET_CONF_CONG_FILL] = { .type = NLA_U32, },
	[DRBD_A_NET_CONF_CONG_EXTENTS] = { .type = NLA_U32, },
	[DRBD_A_NET_CONF_TWO_PRIMARIES] = { .type = NLA_U8, },
	[DRBD_A_NET_CONF_TCP_CORK] = { .type = NLA_U8, },
	[DRBD_A_NET_CONF_ALWAYS_ASBP] = { .type = NLA_U8, },
	[DRBD_A_NET_CONF_USE_RLE] = { .type = NLA_U8, },
	[DRBD_A_NET_CONF_FENCING_POLICY] = { .type = NLA_U32, },
	[DRBD_A_NET_CONF_NAME] = { .type = NLA_NUL_STRING, .len = SHARED_SECRET_MAX, },
	[DRBD_A_NET_CONF_CSUMS_AFTER_CRASH_ONLY] = { .type = NLA_U8, },
	[DRBD_A_NET_CONF_SOCK_CHECK_TIMEO] = { .type = NLA_U32, },
	[DRBD_A_NET_CONF_TRANSPORT_NAME] = { .type = NLA_NUL_STRING, .len = SHARED_SECRET_MAX, },
	[DRBD_A_NET_CONF_MAX_BUFFERS] = { .type = NLA_U32, },
	[DRBD_A_NET_CONF_ALLOW_REMOTE_READ] = { .type = NLA_U8, },
	[DRBD_A_NET_CONF_TLS] = { .type = NLA_U8, },
	[DRBD_A_NET_CONF_TLS_PRIVKEY] = { .type = NLA_S32, },
	[DRBD_A_NET_CONF_TLS_CERTIFICATE] = { .type = NLA_S32, },
	[DRBD_A_NET_CONF_TLS_KEYRING] = { .type = NLA_S32, },
	[DRBD_A_NET_CONF_LOAD_BALANCE_PATHS] = { .type = NLA_U8, },
	[DRBD_A_NET_CONF_RDMA_CTRL_RCVBUF_SIZE] = { .type = NLA_U32, },
	[DRBD_A_NET_CONF_RDMA_CTRL_SNDBUF_SIZE] = { .type = NLA_U32, },
};

const struct nla_policy drbd_new_c_uuid_parms_nl_policy[DRBD_A_NEW_C_UUID_PARMS_FORCE_RESYNC + 1] = {
	[DRBD_A_NEW_C_UUID_PARMS_CLEAR_BM] = { .type = NLA_U8, },
	[DRBD_A_NEW_C_UUID_PARMS_FORCE_RESYNC] = { .type = NLA_U8, },
};

const struct nla_policy drbd_path_parms_nl_policy[DRBD_A_PATH_PARMS_PEER_ADDR + 1] = {
	[DRBD_A_PATH_PARMS_MY_ADDR] = NLA_POLICY_MAX_LEN(128),
	[DRBD_A_PATH_PARMS_PEER_ADDR] = NLA_POLICY_MAX_LEN(128),
};

const struct nla_policy drbd_peer_device_conf_nl_policy[DRBD_A_PEER_DEVICE_CONF_PEER_TIEBREAKER + 1] = {
	[DRBD_A_PEER_DEVICE_CONF_RESYNC_RATE] = { .type = NLA_U32, },
	[DRBD_A_PEER_DEVICE_CONF_C_PLAN_AHEAD] = { .type = NLA_U32, },
	[DRBD_A_PEER_DEVICE_CONF_C_DELAY_TARGET] = { .type = NLA_U32, },
	[DRBD_A_PEER_DEVICE_CONF_C_FILL_TARGET] = { .type = NLA_U32, },
	[DRBD_A_PEER_DEVICE_CONF_C_MAX_RATE] = { .type = NLA_U32, },
	[DRBD_A_PEER_DEVICE_CONF_C_MIN_RATE] = { .type = NLA_U32, },
	[DRBD_A_PEER_DEVICE_CONF_BITMAP] = { .type = NLA_U8, },
	[DRBD_A_PEER_DEVICE_CONF_RESYNC_WITHOUT_REPLICATION] = { .type = NLA_U8, },
	[DRBD_A_PEER_DEVICE_CONF_PEER_TIEBREAKER] = { .type = NLA_U8, },
};

const struct nla_policy drbd_peer_device_info_nl_policy[DRBD_A_PEER_DEVICE_INFO_PEER_RESYNC_SUSP_MAX_PARALLEL + 1] = {
	[DRBD_A_PEER_DEVICE_INFO_PEER_REPL_STATE] = { .type = NLA_U32, },
	[DRBD_A_PEER_DEVICE_INFO_PEER_DISK_STATE] = { .type = NLA_U32, },
	[DRBD_A_PEER_DEVICE_INFO_PEER_RESYNC_SUSP_USER] = { .type = NLA_U32, },
	[DRBD_A_PEER_DEVICE_INFO_PEER_RESYNC_SUSP_PEER] = { .type = NLA_U32, },
	[DRBD_A_PEER_DEVICE_INFO_PEER_RESYNC_SUSP_DEPENDENCY] = { .type = NLA_U32, },
	[DRBD_A_PEER_DEVICE_INFO_PEER_IS_INTENTIONAL_DISKLESS] = { .type = NLA_U8, },
	[DRBD_A_PEER_DEVICE_INFO_PEER_RESYNC_SUSP_MAX_PARALLEL] = { .type = NLA_U32, },
};

const struct nla_policy drbd_peer_device_statistics_nl_policy[DRBD_A_PEER_DEVICE_STATISTICS_PEER_DEV_UUID_FLAGS + 1] = {
	[DRBD_A_PEER_DEVICE_STATISTICS_PEER_DEV_RECEIVED] = { .type = NLA_U64, },
	[DRBD_A_PEER_DEVICE_STATISTICS_PEER_DEV_SENT] = { .type = NLA_U64, },
	[DRBD_A_PEER_DEVICE_STATISTICS_PEER_DEV_PENDING] = { .type = NLA_U32, },
	[DRBD_A_PEER_DEVICE_STATISTICS_PEER_DEV_UNACKED] = { .type = NLA_U32, },
	[DRBD_A_PEER_DEVICE_STATISTICS_PEER_DEV_OUT_OF_SYNC] = { .type = NLA_U64, },
	[DRBD_A_PEER_DEVICE_STATISTICS_PEER_DEV_RESYNC_FAILED] = { .type = NLA_U64, },
	[DRBD_A_PEER_DEVICE_STATISTICS_PEER_DEV_BITMAP_UUID] = { .type = NLA_U64, },
	[DRBD_A_PEER_DEVICE_STATISTICS_PEER_DEV_FLAGS] = { .type = NLA_U32, },
	[DRBD_A_PEER_DEVICE_STATISTICS_PEER_DEV_RS_TOTAL] = { .type = NLA_U64, },
	[DRBD_A_PEER_DEVICE_STATISTICS_PEER_DEV_OV_START_SECTOR] = { .type = NLA_U64, },
	[DRBD_A_PEER_DEVICE_STATISTICS_PEER_DEV_OV_STOP_SECTOR] = { .type = NLA_U64, },
	[DRBD_A_PEER_DEVICE_STATISTICS_PEER_DEV_OV_POSITION] = { .type = NLA_U64, },
	[DRBD_A_PEER_DEVICE_STATISTICS_PEER_DEV_OV_LEFT] = { .type = NLA_U64, },
	[DRBD_A_PEER_DEVICE_STATISTICS_PEER_DEV_OV_SKIPPED] = { .type = NLA_U64, },
	[DRBD_A_PEER_DEVICE_STATISTICS_PEER_DEV_RS_SAME_CSUM] = { .type = NLA_U64, },
	[DRBD_A_PEER_DEVICE_STATISTICS_PEER_DEV_RS_DT_START_MS] = { .type = NLA_U64, },
	[DRBD_A_PEER_DEVICE_STATISTICS_PEER_DEV_RS_PAUSED_MS] = { .type = NLA_U64, },
	[DRBD_A_PEER_DEVICE_STATISTICS_PEER_DEV_RS_DT0_MS] = { .type = NLA_U64, },
	[DRBD_A_PEER_DEVICE_STATISTICS_PEER_DEV_RS_DB0_SECTORS] = { .type = NLA_U64, },
	[DRBD_A_PEER_DEVICE_STATISTICS_PEER_DEV_RS_DT1_MS] = { .type = NLA_U64, },
	[DRBD_A_PEER_DEVICE_STATISTICS_PEER_DEV_RS_DB1_SECTORS] = { .type = NLA_U64, },
	[DRBD_A_PEER_DEVICE_STATISTICS_PEER_DEV_RS_C_SYNC_RATE] = { .type = NLA_U32, },
	[DRBD_A_PEER_DEVICE_STATISTICS_PEER_DEV_UUID_FLAGS] = { .type = NLA_U64, },
};

const struct nla_policy drbd_rename_resource_info_nl_policy[DRBD_A_RENAME_RESOURCE_INFO_RES_NEW_NAME + 1] = {
	[DRBD_A_RENAME_RESOURCE_INFO_RES_NEW_NAME] = { .type = NLA_NUL_STRING, .len = 128, },
};

const struct nla_policy drbd_rename_resource_parms_nl_policy[DRBD_A_RENAME_RESOURCE_PARMS_NEW_RESOURCE_NAME + 1] = {
	[DRBD_A_RENAME_RESOURCE_PARMS_NEW_RESOURCE_NAME] = { .type = NLA_NUL_STRING, .len = 128, },
};

const struct nla_policy drbd_res_opts_nl_policy[DRBD_A_RES_OPTS_EXPLICIT_DRBD8_COMPAT + 1] = {
	[DRBD_A_RES_OPTS_CPU_MASK] = { .type = NLA_NUL_STRING, .len = DRBD_CPU_MASK_SIZE, },
	[DRBD_A_RES_OPTS_ON_NO_DATA] = { .type = NLA_U32, },
	[DRBD_A_RES_OPTS_AUTO_PROMOTE] = { .type = NLA_U8, },
	[DRBD_A_RES_OPTS_NODE_ID] = { .type = NLA_U32, },
	[DRBD_A_RES_OPTS_PEER_ACK_WINDOW] = { .type = NLA_U32, },
	[DRBD_A_RES_OPTS_TWOPC_TIMEOUT] = { .type = NLA_U32, },
	[DRBD_A_RES_OPTS_TWOPC_RETRY_TIMEOUT] = { .type = NLA_U32, },
	[DRBD_A_RES_OPTS_PEER_ACK_DELAY] = { .type = NLA_U32, },
	[DRBD_A_RES_OPTS_AUTO_PROMOTE_TIMEOUT] = { .type = NLA_U32, },
	[DRBD_A_RES_OPTS_NR_REQUESTS] = { .type = NLA_U32, },
	[DRBD_A_RES_OPTS_QUORUM] = { .type = NLA_S32, },
	[DRBD_A_RES_OPTS_ON_NO_QUORUM] = { .type = NLA_U32, },
	[DRBD_A_RES_OPTS_QUORUM_MIN_REDUNDANCY] = { .type = NLA_S32, },
	[DRBD_A_RES_OPTS_ON_SUSP_PRIMARY_OUTDATED] = { .type = NLA_U32, },
	[DRBD_A_RES_OPTS_DRBD8_COMPAT_MODE] = { .type = NLA_U8, },
	[DRBD_A_RES_OPTS_EXPLICIT_DRBD8_COMPAT] = { .type = NLA_U8, },
};

const struct nla_policy drbd_resize_parms_nl_policy[DRBD_A_RESIZE_PARMS_AL_STRIPE_SIZE + 1] = {
	[DRBD_A_RESIZE_PARMS_RESIZE_SIZE] = { .type = NLA_U64, },
	[DRBD_A_RESIZE_PARMS_RESIZE_FORCE] = { .type = NLA_U8, },
	[DRBD_A_RESIZE_PARMS_NO_RESYNC] = { .type = NLA_U8, },
	[DRBD_A_RESIZE_PARMS_AL_STRIPES] = { .type = NLA_U32, },
	[DRBD_A_RESIZE_PARMS_AL_STRIPE_SIZE] = { .type = NLA_U32, },
};

const struct nla_policy drbd_resource_info_nl_policy[DRBD_A_RESOURCE_INFO_RES_FAIL_IO + 1] = {
	[DRBD_A_RESOURCE_INFO_RES_ROLE] = { .type = NLA_U32, },
	[DRBD_A_RESOURCE_INFO_RES_SUSP] = { .type = NLA_U8, },
	[DRBD_A_RESOURCE_INFO_RES_SUSP_NOD] = { .type = NLA_U8, },
	[DRBD_A_RESOURCE_INFO_RES_SUSP_FEN] = { .type = NLA_U8, },
	[DRBD_A_RESOURCE_INFO_RES_SUSP_QUORUM] = { .type = NLA_U8, },
	[DRBD_A_RESOURCE_INFO_RES_FAIL_IO] = { .type = NLA_U8, },
};

const struct nla_policy drbd_resource_statistics_nl_policy[DRBD_A_RESOURCE_STATISTICS_RES_STAT_WRITE_ORDERING + 1] = {
	[DRBD_A_RESOURCE_STATISTICS_RES_STAT_WRITE_ORDERING] = { .type = NLA_U32, },
};

const struct nla_policy drbd_set_role_parms_nl_policy[DRBD_A_SET_ROLE_PARMS_FORCE + 1] = {
	[DRBD_A_SET_ROLE_PARMS_FORCE] = { .type = NLA_U8, },
};

const struct nla_policy drbd_start_ov_parms_nl_policy[DRBD_A_START_OV_PARMS_OV_STOP_SECTOR + 1] = {
	[DRBD_A_START_OV_PARMS_OV_START_SECTOR] = { .type = NLA_U64, },
	[DRBD_A_START_OV_PARMS_OV_STOP_SECTOR] = { .type = NLA_U64, },
};

const struct nla_policy drbd_suspend_io_parms_nl_policy[DRBD_A_SUSPEND_IO_PARMS_BDEV_FREEZE + 1] = {
	[DRBD_A_SUSPEND_IO_PARMS_BDEV_FREEZE] = { .type = NLA_U8, },
};

const struct nla_policy drbd_timeout_parms_nl_policy[DRBD_A_TIMEOUT_PARMS_TIMEOUT_TYPE + 1] = {
	[DRBD_A_TIMEOUT_PARMS_TIMEOUT_TYPE] = { .type = NLA_U32, },
};

const struct nla_policy drbd_tla_nl_policy[DRBD_TLA_NL_POLICY_LEN] = {
	[DRBD_NLA_CFG_REPLY] = { .type = NLA_NESTED },
	[DRBD_NLA_CFG_CONTEXT] = { .type = NLA_NESTED },
	[DRBD_NLA_DISK_CONF] = { .type = NLA_NESTED },
	[DRBD_NLA_RESOURCE_OPTS] = { .type = NLA_NESTED },
	[DRBD_NLA_NET_CONF] = { .type = NLA_NESTED },
	[DRBD_NLA_SET_ROLE_PARMS] = { .type = NLA_NESTED },
	[DRBD_NLA_RESIZE_PARMS] = { .type = NLA_NESTED },
	[DRBD_NLA_START_OV_PARMS] = { .type = NLA_NESTED },
	[DRBD_NLA_NEW_C_UUID_PARMS] = { .type = NLA_NESTED },
	[DRBD_NLA_TIMEOUT_PARMS] = { .type = NLA_NESTED },
	[DRBD_NLA_DISCONNECT_PARMS] = { .type = NLA_NESTED },
	[DRBD_NLA_DETACH_PARMS] = { .type = NLA_NESTED },
	[DRBD_NLA_DEVICE_CONF] = { .type = NLA_NESTED },
	[DRBD_NLA_RESOURCE_INFO] = { .type = NLA_NESTED },
	[DRBD_NLA_DEVICE_INFO] = { .type = NLA_NESTED },
	[DRBD_NLA_CONNECTION_INFO] = { .type = NLA_NESTED },
	[DRBD_NLA_PEER_DEVICE_INFO] = { .type = NLA_NESTED },
	[DRBD_NLA_RESOURCE_STATISTICS] = { .type = NLA_NESTED },
	[DRBD_NLA_DEVICE_STATISTICS] = { .type = NLA_NESTED },
	[DRBD_NLA_CONNECTION_STATISTICS] = { .type = NLA_NESTED },
	[DRBD_NLA_PEER_DEVICE_STATISTICS] = { .type = NLA_NESTED },
	[DRBD_NLA_NOTIFICATION_HEADER] = { .type = NLA_NESTED },
	[DRBD_NLA_HELPER] = { .type = NLA_NESTED },
	[DRBD_NLA_INVALIDATE_PARMS] = { .type = NLA_NESTED },
	[DRBD_NLA_FORGET_PEER_PARMS] = { .type = NLA_NESTED },
	[DRBD_NLA_PEER_DEVICE_OPTS] = { .type = NLA_NESTED },
	[DRBD_NLA_PATH_PARMS] = { .type = NLA_NESTED },
	[DRBD_NLA_CONNECT_PARMS] = { .type = NLA_NESTED },
	[DRBD_NLA_PATH_INFO] = { .type = NLA_NESTED },
	[DRBD_NLA_RENAME_RESOURCE_PARMS] = { .type = NLA_NESTED },
	[DRBD_NLA_RENAME_RESOURCE_INFO] = { .type = NLA_NESTED },
	[DRBD_NLA_INVAL_PEER_PARAMS] = { .type = NLA_NESTED },
	[DRBD_NLA_SUSPEND_IO_PARAMS] = { .type = NLA_NESTED },
};

static int __drbd_cfg_reply_from_attrs(struct drbd_cfg_reply *s,
		struct nlattr ***ret_nested_attribute_table,
		struct genl_info *info)
{
	const int maxtype = DRBD_A_DRBD_CFG_REPLY_INFO_TEXT;
	struct nlattr *tla = info->attrs[DRBD_NLA_CFG_REPLY];
	struct nlattr *ntb[DRBD_A_DRBD_CFG_REPLY_INFO_TEXT + 1];
	struct nlattr *nla;
	int err = 0;

	if (ret_nested_attribute_table)
		*ret_nested_attribute_table = NULL;
	if (!tla)
		return -ENOMSG;
	err = nla_parse_nested(ntb, maxtype, tla, drbd_drbd_cfg_reply_nl_policy);
	if (err)
		return err;

	nla = ntb[DRBD_A_DRBD_CFG_REPLY_INFO_TEXT];
	if (nla && s)
		s->info_text_len = nla_strlcpy(s->info_text, nla, 0);

	if (ret_nested_attribute_table && (!err || err == -ENOMSG))
		memcpy(ret_nested_attribute_table, ntb, sizeof(ntb));
	return err;
}

int drbd_cfg_reply_from_attrs(struct drbd_cfg_reply *s,
				struct genl_info *info)
{
	return __drbd_cfg_reply_from_attrs(s, NULL, info);
}

int drbd_cfg_reply_ntb_from_attrs(
			struct nlattr ***ret_nested_attribute_table,
			struct genl_info *info)
{
	return __drbd_cfg_reply_from_attrs(NULL, ret_nested_attribute_table, info);
}

static int __drbd_cfg_context_from_attrs(struct drbd_cfg_context *s,
		struct nlattr ***ret_nested_attribute_table,
		struct genl_info *info)
{
	const int maxtype = DRBD_A_DRBD_CFG_CONTEXT_CTX_PEER_NODE_ID;
	struct nlattr *tla = info->attrs[DRBD_NLA_CFG_CONTEXT];
	struct nlattr *ntb[DRBD_A_DRBD_CFG_CONTEXT_CTX_PEER_NODE_ID + 1];
	struct nlattr *nla;
	int err = 0;

	if (ret_nested_attribute_table)
		*ret_nested_attribute_table = NULL;
	if (!tla)
		return -ENOMSG;
	err = nla_parse_nested(ntb, maxtype, tla, drbd_drbd_cfg_context_nl_policy);
	if (err)
		return err;

	nla = ntb[DRBD_A_DRBD_CFG_CONTEXT_CTX_PEER_NODE_ID];
	if (nla && s)
		s->ctx_peer_node_id = nla_get_u32(nla);

	nla = ntb[DRBD_A_DRBD_CFG_CONTEXT_CTX_VOLUME];
	if (nla && s)
		s->ctx_volume = nla_get_u32(nla);

	nla = ntb[DRBD_A_DRBD_CFG_CONTEXT_CTX_RESOURCE_NAME];
	if (nla && s)
		s->ctx_resource_name_len = nla_strlcpy(s->ctx_resource_name, nla, 128);

	nla = ntb[DRBD_A_DRBD_CFG_CONTEXT_CTX_MY_ADDR];
	if (nla && s)
		s->ctx_my_addr_len = nla_memcpy(s->ctx_my_addr, nla, 128);

	nla = ntb[DRBD_A_DRBD_CFG_CONTEXT_CTX_PEER_ADDR];
	if (nla && s)
		s->ctx_peer_addr_len = nla_memcpy(s->ctx_peer_addr, nla, 128);

	nla = ntb[DRBD_A_DRBD_CFG_CONTEXT_CTX_CONN_NAME];
	if (nla && s)
		s->ctx_conn_name_len = nla_strlcpy(s->ctx_conn_name, nla, SHARED_SECRET_MAX);

	if (ret_nested_attribute_table && (!err || err == -ENOMSG))
		memcpy(ret_nested_attribute_table, ntb, sizeof(ntb));
	return err;
}

int drbd_cfg_context_from_attrs(struct drbd_cfg_context *s,
				struct genl_info *info)
{
	return __drbd_cfg_context_from_attrs(s, NULL, info);
}

int drbd_cfg_context_ntb_from_attrs(
			struct nlattr ***ret_nested_attribute_table,
			struct genl_info *info)
{
	return __drbd_cfg_context_from_attrs(NULL, ret_nested_attribute_table, info);
}

static int __disk_conf_from_attrs(struct disk_conf *s,
		struct nlattr ***ret_nested_attribute_table,
		struct genl_info *info)
{
	const int maxtype = DRBD_A_DISK_CONF_D_BITMAP;
	struct nlattr *tla = info->attrs[DRBD_NLA_DISK_CONF];
	struct nlattr *ntb[DRBD_A_DISK_CONF_D_BITMAP + 1];
	struct nlattr *nla;
	int err = 0;

	if (ret_nested_attribute_table)
		*ret_nested_attribute_table = NULL;
	if (!tla)
		return -ENOMSG;
	err = nla_parse_nested(ntb, maxtype, tla, drbd_disk_conf_nl_policy);
	if (err)
		return err;

	nla = ntb[DRBD_A_DISK_CONF_BACKING_DEV];
	if (nla) {
		if (s)
			s->backing_dev_len = nla_strlcpy(s->backing_dev, nla, 128);
	} else {
		fprintf(stderr, "<< missing required attr: backing_dev\n");
		err = -ENOMSG;
	}

	nla = ntb[DRBD_A_DISK_CONF_META_DEV];
	if (nla) {
		if (s)
			s->meta_dev_len = nla_strlcpy(s->meta_dev, nla, 128);
	} else {
		fprintf(stderr, "<< missing required attr: meta_dev\n");
		err = -ENOMSG;
	}

	nla = ntb[DRBD_A_DISK_CONF_META_DEV_IDX];
	if (nla) {
		if (s)
			s->meta_dev_idx = nla_get_s32(nla);
	} else {
		fprintf(stderr, "<< missing required attr: meta_dev_idx\n");
		err = -ENOMSG;
	}

	nla = ntb[DRBD_A_DISK_CONF_DISK_SIZE];
	if (nla && s)
		s->disk_size = nla_get_u64(nla);

	nla = ntb[DRBD_A_DISK_CONF_ON_IO_ERROR];
	if (nla && s)
		s->on_io_error = nla_get_u32(nla);

	nla = ntb[DRBD_A_DISK_CONF_RESYNC_AFTER];
	if (nla && s)
		s->resync_after = nla_get_s32(nla);

	nla = ntb[DRBD_A_DISK_CONF_AL_EXTENTS];
	if (nla && s)
		s->al_extents = nla_get_u32(nla);

	nla = ntb[DRBD_A_DISK_CONF_DISK_BARRIER];
	if (nla && s)
		s->disk_barrier = nla_get_u8(nla);

	nla = ntb[DRBD_A_DISK_CONF_DISK_FLUSHES];
	if (nla && s)
		s->disk_flushes = nla_get_u8(nla);

	nla = ntb[DRBD_A_DISK_CONF_DISK_DRAIN];
	if (nla && s)
		s->disk_drain = nla_get_u8(nla);

	nla = ntb[DRBD_A_DISK_CONF_MD_FLUSHES];
	if (nla && s)
		s->md_flushes = nla_get_u8(nla);

	nla = ntb[DRBD_A_DISK_CONF_DISK_TIMEOUT];
	if (nla && s)
		s->disk_timeout = nla_get_u32(nla);

	nla = ntb[DRBD_A_DISK_CONF_READ_BALANCING];
	if (nla && s)
		s->read_balancing = nla_get_u32(nla);

	nla = ntb[DRBD_A_DISK_CONF_UNPLUG_WATERMARK];
	if (nla && s)
		s->unplug_watermark = nla_get_u32(nla);

	nla = ntb[DRBD_A_DISK_CONF_RS_DISCARD_GRANULARITY];
	if (nla && s)
		s->rs_discard_granularity = nla_get_u32(nla);

	nla = ntb[DRBD_A_DISK_CONF_AL_UPDATES];
	if (nla && s)
		s->al_updates = nla_get_u8(nla);

	nla = ntb[DRBD_A_DISK_CONF_DISCARD_ZEROES_IF_ALIGNED];
	if (nla && s)
		s->discard_zeroes_if_aligned = nla_get_u8(nla);

	nla = ntb[DRBD_A_DISK_CONF_DISABLE_WRITE_SAME];
	if (nla && s)
		s->disable_write_same = nla_get_u8(nla);

	nla = ntb[DRBD_A_DISK_CONF_D_BITMAP];
	if (nla && s)
		s->d_bitmap = nla_get_u8(nla);

	if (ret_nested_attribute_table && (!err || err == -ENOMSG))
		memcpy(ret_nested_attribute_table, ntb, sizeof(ntb));
	return err;
}

int disk_conf_from_attrs(struct disk_conf *s,
				struct genl_info *info)
{
	return __disk_conf_from_attrs(s, NULL, info);
}

int disk_conf_ntb_from_attrs(
			struct nlattr ***ret_nested_attribute_table,
			struct genl_info *info)
{
	return __disk_conf_from_attrs(NULL, ret_nested_attribute_table, info);
}

static int __res_opts_from_attrs(struct res_opts *s,
		struct nlattr ***ret_nested_attribute_table,
		struct genl_info *info)
{
	const int maxtype = DRBD_A_RES_OPTS_EXPLICIT_DRBD8_COMPAT;
	struct nlattr *tla = info->attrs[DRBD_NLA_RESOURCE_OPTS];
	struct nlattr *ntb[DRBD_A_RES_OPTS_EXPLICIT_DRBD8_COMPAT + 1];
	struct nlattr *nla;
	int err = 0;

	if (ret_nested_attribute_table)
		*ret_nested_attribute_table = NULL;
	if (!tla)
		return -ENOMSG;
	err = nla_parse_nested(ntb, maxtype, tla, drbd_res_opts_nl_policy);
	if (err)
		return err;

	nla = ntb[DRBD_A_RES_OPTS_CPU_MASK];
	if (nla && s)
		s->cpu_mask_len = nla_strlcpy(s->cpu_mask, nla, DRBD_CPU_MASK_SIZE);

	nla = ntb[DRBD_A_RES_OPTS_ON_NO_DATA];
	if (nla && s)
		s->on_no_data = nla_get_u32(nla);

	nla = ntb[DRBD_A_RES_OPTS_AUTO_PROMOTE];
	if (nla && s)
		s->auto_promote = nla_get_u8(nla);

	nla = ntb[DRBD_A_RES_OPTS_NODE_ID];
	if (nla) {
		if (s)
			s->node_id = nla_get_u32(nla);
	} else {
		fprintf(stderr, "<< missing required attr: node_id\n");
		err = -ENOMSG;
	}

	nla = ntb[DRBD_A_RES_OPTS_PEER_ACK_WINDOW];
	if (nla && s)
		s->peer_ack_window = nla_get_u32(nla);

	nla = ntb[DRBD_A_RES_OPTS_TWOPC_TIMEOUT];
	if (nla && s)
		s->twopc_timeout = nla_get_u32(nla);

	nla = ntb[DRBD_A_RES_OPTS_TWOPC_RETRY_TIMEOUT];
	if (nla && s)
		s->twopc_retry_timeout = nla_get_u32(nla);

	nla = ntb[DRBD_A_RES_OPTS_PEER_ACK_DELAY];
	if (nla && s)
		s->peer_ack_delay = nla_get_u32(nla);

	nla = ntb[DRBD_A_RES_OPTS_AUTO_PROMOTE_TIMEOUT];
	if (nla && s)
		s->auto_promote_timeout = nla_get_u32(nla);

	nla = ntb[DRBD_A_RES_OPTS_NR_REQUESTS];
	if (nla && s)
		s->nr_requests = nla_get_u32(nla);

	nla = ntb[DRBD_A_RES_OPTS_QUORUM];
	if (nla && s)
		s->quorum = nla_get_s32(nla);

	nla = ntb[DRBD_A_RES_OPTS_ON_NO_QUORUM];
	if (nla && s)
		s->on_no_quorum = nla_get_u32(nla);

	nla = ntb[DRBD_A_RES_OPTS_QUORUM_MIN_REDUNDANCY];
	if (nla && s)
		s->quorum_min_redundancy = nla_get_s32(nla);

	nla = ntb[DRBD_A_RES_OPTS_ON_SUSP_PRIMARY_OUTDATED];
	if (nla && s)
		s->on_susp_primary_outdated = nla_get_u32(nla);

	nla = ntb[DRBD_A_RES_OPTS_DRBD8_COMPAT_MODE];
	if (nla && s)
		s->drbd8_compat_mode = nla_get_u8(nla);

	nla = ntb[DRBD_A_RES_OPTS_EXPLICIT_DRBD8_COMPAT];
	if (nla && s)
		s->explicit_drbd8_compat = nla_get_u8(nla);

	if (ret_nested_attribute_table && (!err || err == -ENOMSG))
		memcpy(ret_nested_attribute_table, ntb, sizeof(ntb));
	return err;
}

int res_opts_from_attrs(struct res_opts *s,
				struct genl_info *info)
{
	return __res_opts_from_attrs(s, NULL, info);
}

int res_opts_ntb_from_attrs(
			struct nlattr ***ret_nested_attribute_table,
			struct genl_info *info)
{
	return __res_opts_from_attrs(NULL, ret_nested_attribute_table, info);
}

static int __net_conf_from_attrs(struct net_conf *s,
		struct nlattr ***ret_nested_attribute_table,
		struct genl_info *info)
{
	const int maxtype = DRBD_A_NET_CONF_RDMA_CTRL_SNDBUF_SIZE;
	struct nlattr *tla = info->attrs[DRBD_NLA_NET_CONF];
	struct nlattr *ntb[DRBD_A_NET_CONF_RDMA_CTRL_SNDBUF_SIZE + 1];
	struct nlattr *nla;
	int err = 0;

	if (ret_nested_attribute_table)
		*ret_nested_attribute_table = NULL;
	if (!tla)
		return -ENOMSG;
	err = nla_parse_nested(ntb, maxtype, tla, drbd_net_conf_nl_policy);
	if (err)
		return err;

	nla = ntb[DRBD_A_NET_CONF_SHARED_SECRET];
	if (nla && s)
		s->shared_secret_len = nla_strlcpy(s->shared_secret, nla, SHARED_SECRET_MAX);

	nla = ntb[DRBD_A_NET_CONF_CRAM_HMAC_ALG];
	if (nla && s)
		s->cram_hmac_alg_len = nla_strlcpy(s->cram_hmac_alg, nla, SHARED_SECRET_MAX);

	nla = ntb[DRBD_A_NET_CONF_INTEGRITY_ALG];
	if (nla && s)
		s->integrity_alg_len = nla_strlcpy(s->integrity_alg, nla, SHARED_SECRET_MAX);

	nla = ntb[DRBD_A_NET_CONF_VERIFY_ALG];
	if (nla && s)
		s->verify_alg_len = nla_strlcpy(s->verify_alg, nla, SHARED_SECRET_MAX);

	nla = ntb[DRBD_A_NET_CONF_CSUMS_ALG];
	if (nla && s)
		s->csums_alg_len = nla_strlcpy(s->csums_alg, nla, SHARED_SECRET_MAX);

	nla = ntb[DRBD_A_NET_CONF_WIRE_PROTOCOL];
	if (nla && s)
		s->wire_protocol = nla_get_u32(nla);

	nla = ntb[DRBD_A_NET_CONF_CONNECT_INT];
	if (nla && s)
		s->connect_int = nla_get_u32(nla);

	nla = ntb[DRBD_A_NET_CONF_TIMEOUT];
	if (nla && s)
		s->timeout = nla_get_u32(nla);

	nla = ntb[DRBD_A_NET_CONF_PING_INT];
	if (nla && s)
		s->ping_int = nla_get_u32(nla);

	nla = ntb[DRBD_A_NET_CONF_PING_TIMEO];
	if (nla && s)
		s->ping_timeo = nla_get_u32(nla);

	nla = ntb[DRBD_A_NET_CONF_SNDBUF_SIZE];
	if (nla && s)
		s->sndbuf_size = nla_get_u32(nla);

	nla = ntb[DRBD_A_NET_CONF_RCVBUF_SIZE];
	if (nla && s)
		s->rcvbuf_size = nla_get_u32(nla);

	nla = ntb[DRBD_A_NET_CONF_KO_COUNT];
	if (nla && s)
		s->ko_count = nla_get_u32(nla);

	nla = ntb[DRBD_A_NET_CONF_MAX_EPOCH_SIZE];
	if (nla && s)
		s->max_epoch_size = nla_get_u32(nla);

	nla = ntb[DRBD_A_NET_CONF_AFTER_SB_0P];
	if (nla && s)
		s->after_sb_0p = nla_get_u32(nla);

	nla = ntb[DRBD_A_NET_CONF_AFTER_SB_1P];
	if (nla && s)
		s->after_sb_1p = nla_get_u32(nla);

	nla = ntb[DRBD_A_NET_CONF_AFTER_SB_2P];
	if (nla && s)
		s->after_sb_2p = nla_get_u32(nla);

	nla = ntb[DRBD_A_NET_CONF_RR_CONFLICT];
	if (nla && s)
		s->rr_conflict = nla_get_u32(nla);

	nla = ntb[DRBD_A_NET_CONF_ON_CONGESTION];
	if (nla && s)
		s->on_congestion = nla_get_u32(nla);

	nla = ntb[DRBD_A_NET_CONF_CONG_FILL];
	if (nla && s)
		s->cong_fill = nla_get_u32(nla);

	nla = ntb[DRBD_A_NET_CONF_CONG_EXTENTS];
	if (nla && s)
		s->cong_extents = nla_get_u32(nla);

	nla = ntb[DRBD_A_NET_CONF_TWO_PRIMARIES];
	if (nla && s)
		s->two_primaries = nla_get_u8(nla);

	nla = ntb[DRBD_A_NET_CONF_TCP_CORK];
	if (nla && s)
		s->tcp_cork = nla_get_u8(nla);

	nla = ntb[DRBD_A_NET_CONF_ALWAYS_ASBP];
	if (nla && s)
		s->always_asbp = nla_get_u8(nla);

	nla = ntb[DRBD_A_NET_CONF_USE_RLE];
	if (nla && s)
		s->use_rle = nla_get_u8(nla);

	nla = ntb[DRBD_A_NET_CONF_FENCING_POLICY];
	if (nla && s)
		s->fencing_policy = nla_get_u32(nla);

	nla = ntb[DRBD_A_NET_CONF_NAME];
	if (nla && s)
		s->name_len = nla_strlcpy(s->name, nla, SHARED_SECRET_MAX);

	nla = ntb[DRBD_A_NET_CONF_CSUMS_AFTER_CRASH_ONLY];
	if (nla && s)
		s->csums_after_crash_only = nla_get_u8(nla);

	nla = ntb[DRBD_A_NET_CONF_SOCK_CHECK_TIMEO];
	if (nla && s)
		s->sock_check_timeo = nla_get_u32(nla);

	nla = ntb[DRBD_A_NET_CONF_TRANSPORT_NAME];
	if (nla && s)
		s->transport_name_len = nla_strlcpy(s->transport_name, nla, SHARED_SECRET_MAX);

	nla = ntb[DRBD_A_NET_CONF_MAX_BUFFERS];
	if (nla && s)
		s->max_buffers = nla_get_u32(nla);

	nla = ntb[DRBD_A_NET_CONF_ALLOW_REMOTE_READ];
	if (nla && s)
		s->allow_remote_read = nla_get_u8(nla);

	nla = ntb[DRBD_A_NET_CONF_TLS];
	if (nla && s)
		s->tls = nla_get_u8(nla);

	nla = ntb[DRBD_A_NET_CONF_TLS_PRIVKEY];
	if (nla && s)
		s->tls_privkey = nla_get_s32(nla);

	nla = ntb[DRBD_A_NET_CONF_TLS_CERTIFICATE];
	if (nla && s)
		s->tls_certificate = nla_get_s32(nla);

	nla = ntb[DRBD_A_NET_CONF_TLS_KEYRING];
	if (nla && s)
		s->tls_keyring = nla_get_s32(nla);

	nla = ntb[DRBD_A_NET_CONF_LOAD_BALANCE_PATHS];
	if (nla && s)
		s->load_balance_paths = nla_get_u8(nla);

	nla = ntb[DRBD_A_NET_CONF_RDMA_CTRL_RCVBUF_SIZE];
	if (nla && s)
		s->rdma_ctrl_rcvbuf_size = nla_get_u32(nla);

	nla = ntb[DRBD_A_NET_CONF_RDMA_CTRL_SNDBUF_SIZE];
	if (nla && s)
		s->rdma_ctrl_sndbuf_size = nla_get_u32(nla);

	if (ret_nested_attribute_table && (!err || err == -ENOMSG))
		memcpy(ret_nested_attribute_table, ntb, sizeof(ntb));
	return err;
}

int net_conf_from_attrs(struct net_conf *s,
				struct genl_info *info)
{
	return __net_conf_from_attrs(s, NULL, info);
}

int net_conf_ntb_from_attrs(
			struct nlattr ***ret_nested_attribute_table,
			struct genl_info *info)
{
	return __net_conf_from_attrs(NULL, ret_nested_attribute_table, info);
}

static int __set_role_parms_from_attrs(struct set_role_parms *s,
		struct nlattr ***ret_nested_attribute_table,
		struct genl_info *info)
{
	const int maxtype = DRBD_A_SET_ROLE_PARMS_FORCE;
	struct nlattr *tla = info->attrs[DRBD_NLA_SET_ROLE_PARMS];
	struct nlattr *ntb[DRBD_A_SET_ROLE_PARMS_FORCE + 1];
	struct nlattr *nla;
	int err = 0;

	if (ret_nested_attribute_table)
		*ret_nested_attribute_table = NULL;
	if (!tla)
		return -ENOMSG;
	err = nla_parse_nested(ntb, maxtype, tla, drbd_set_role_parms_nl_policy);
	if (err)
		return err;

	nla = ntb[DRBD_A_SET_ROLE_PARMS_FORCE];
	if (nla && s)
		s->force = nla_get_u8(nla);

	if (ret_nested_attribute_table && (!err || err == -ENOMSG))
		memcpy(ret_nested_attribute_table, ntb, sizeof(ntb));
	return err;
}

int set_role_parms_from_attrs(struct set_role_parms *s,
				struct genl_info *info)
{
	return __set_role_parms_from_attrs(s, NULL, info);
}

int set_role_parms_ntb_from_attrs(
			struct nlattr ***ret_nested_attribute_table,
			struct genl_info *info)
{
	return __set_role_parms_from_attrs(NULL, ret_nested_attribute_table, info);
}

static int __resize_parms_from_attrs(struct resize_parms *s,
		struct nlattr ***ret_nested_attribute_table,
		struct genl_info *info)
{
	const int maxtype = DRBD_A_RESIZE_PARMS_AL_STRIPE_SIZE;
	struct nlattr *tla = info->attrs[DRBD_NLA_RESIZE_PARMS];
	struct nlattr *ntb[DRBD_A_RESIZE_PARMS_AL_STRIPE_SIZE + 1];
	struct nlattr *nla;
	int err = 0;

	if (ret_nested_attribute_table)
		*ret_nested_attribute_table = NULL;
	if (!tla)
		return -ENOMSG;
	err = nla_parse_nested(ntb, maxtype, tla, drbd_resize_parms_nl_policy);
	if (err)
		return err;

	nla = ntb[DRBD_A_RESIZE_PARMS_RESIZE_SIZE];
	if (nla && s)
		s->resize_size = nla_get_u64(nla);

	nla = ntb[DRBD_A_RESIZE_PARMS_RESIZE_FORCE];
	if (nla && s)
		s->resize_force = nla_get_u8(nla);

	nla = ntb[DRBD_A_RESIZE_PARMS_NO_RESYNC];
	if (nla && s)
		s->no_resync = nla_get_u8(nla);

	nla = ntb[DRBD_A_RESIZE_PARMS_AL_STRIPES];
	if (nla && s)
		s->al_stripes = nla_get_u32(nla);

	nla = ntb[DRBD_A_RESIZE_PARMS_AL_STRIPE_SIZE];
	if (nla && s)
		s->al_stripe_size = nla_get_u32(nla);

	if (ret_nested_attribute_table && (!err || err == -ENOMSG))
		memcpy(ret_nested_attribute_table, ntb, sizeof(ntb));
	return err;
}

int resize_parms_from_attrs(struct resize_parms *s,
				struct genl_info *info)
{
	return __resize_parms_from_attrs(s, NULL, info);
}

int resize_parms_ntb_from_attrs(
			struct nlattr ***ret_nested_attribute_table,
			struct genl_info *info)
{
	return __resize_parms_from_attrs(NULL, ret_nested_attribute_table, info);
}

static int __start_ov_parms_from_attrs(struct start_ov_parms *s,
		struct nlattr ***ret_nested_attribute_table,
		struct genl_info *info)
{
	const int maxtype = DRBD_A_START_OV_PARMS_OV_STOP_SECTOR;
	struct nlattr *tla = info->attrs[DRBD_NLA_START_OV_PARMS];
	struct nlattr *ntb[DRBD_A_START_OV_PARMS_OV_STOP_SECTOR + 1];
	struct nlattr *nla;
	int err = 0;

	if (ret_nested_attribute_table)
		*ret_nested_attribute_table = NULL;
	if (!tla)
		return -ENOMSG;
	err = nla_parse_nested(ntb, maxtype, tla, drbd_start_ov_parms_nl_policy);
	if (err)
		return err;

	nla = ntb[DRBD_A_START_OV_PARMS_OV_START_SECTOR];
	if (nla && s)
		s->ov_start_sector = nla_get_u64(nla);

	nla = ntb[DRBD_A_START_OV_PARMS_OV_STOP_SECTOR];
	if (nla && s)
		s->ov_stop_sector = nla_get_u64(nla);

	if (ret_nested_attribute_table && (!err || err == -ENOMSG))
		memcpy(ret_nested_attribute_table, ntb, sizeof(ntb));
	return err;
}

int start_ov_parms_from_attrs(struct start_ov_parms *s,
				struct genl_info *info)
{
	return __start_ov_parms_from_attrs(s, NULL, info);
}

int start_ov_parms_ntb_from_attrs(
			struct nlattr ***ret_nested_attribute_table,
			struct genl_info *info)
{
	return __start_ov_parms_from_attrs(NULL, ret_nested_attribute_table, info);
}

static int __new_c_uuid_parms_from_attrs(struct new_c_uuid_parms *s,
		struct nlattr ***ret_nested_attribute_table,
		struct genl_info *info)
{
	const int maxtype = DRBD_A_NEW_C_UUID_PARMS_FORCE_RESYNC;
	struct nlattr *tla = info->attrs[DRBD_NLA_NEW_C_UUID_PARMS];
	struct nlattr *ntb[DRBD_A_NEW_C_UUID_PARMS_FORCE_RESYNC + 1];
	struct nlattr *nla;
	int err = 0;

	if (ret_nested_attribute_table)
		*ret_nested_attribute_table = NULL;
	if (!tla)
		return -ENOMSG;
	err = nla_parse_nested(ntb, maxtype, tla, drbd_new_c_uuid_parms_nl_policy);
	if (err)
		return err;

	nla = ntb[DRBD_A_NEW_C_UUID_PARMS_CLEAR_BM];
	if (nla && s)
		s->clear_bm = nla_get_u8(nla);

	nla = ntb[DRBD_A_NEW_C_UUID_PARMS_FORCE_RESYNC];
	if (nla && s)
		s->force_resync = nla_get_u8(nla);

	if (ret_nested_attribute_table && (!err || err == -ENOMSG))
		memcpy(ret_nested_attribute_table, ntb, sizeof(ntb));
	return err;
}

int new_c_uuid_parms_from_attrs(struct new_c_uuid_parms *s,
				struct genl_info *info)
{
	return __new_c_uuid_parms_from_attrs(s, NULL, info);
}

int new_c_uuid_parms_ntb_from_attrs(
			struct nlattr ***ret_nested_attribute_table,
			struct genl_info *info)
{
	return __new_c_uuid_parms_from_attrs(NULL, ret_nested_attribute_table, info);
}

static int __timeout_parms_from_attrs(struct timeout_parms *s,
		struct nlattr ***ret_nested_attribute_table,
		struct genl_info *info)
{
	const int maxtype = DRBD_A_TIMEOUT_PARMS_TIMEOUT_TYPE;
	struct nlattr *tla = info->attrs[DRBD_NLA_TIMEOUT_PARMS];
	struct nlattr *ntb[DRBD_A_TIMEOUT_PARMS_TIMEOUT_TYPE + 1];
	struct nlattr *nla;
	int err = 0;

	if (ret_nested_attribute_table)
		*ret_nested_attribute_table = NULL;
	if (!tla)
		return -ENOMSG;
	err = nla_parse_nested(ntb, maxtype, tla, drbd_timeout_parms_nl_policy);
	if (err)
		return err;

	nla = ntb[DRBD_A_TIMEOUT_PARMS_TIMEOUT_TYPE];
	if (nla) {
		if (s)
			s->timeout_type = nla_get_u32(nla);
	} else {
		fprintf(stderr, "<< missing required attr: timeout_type\n");
		err = -ENOMSG;
	}

	if (ret_nested_attribute_table && (!err || err == -ENOMSG))
		memcpy(ret_nested_attribute_table, ntb, sizeof(ntb));
	return err;
}

int timeout_parms_from_attrs(struct timeout_parms *s,
				struct genl_info *info)
{
	return __timeout_parms_from_attrs(s, NULL, info);
}

int timeout_parms_ntb_from_attrs(
			struct nlattr ***ret_nested_attribute_table,
			struct genl_info *info)
{
	return __timeout_parms_from_attrs(NULL, ret_nested_attribute_table, info);
}

static int __disconnect_parms_from_attrs(struct disconnect_parms *s,
		struct nlattr ***ret_nested_attribute_table,
		struct genl_info *info)
{
	const int maxtype = DRBD_A_DISCONNECT_PARMS_FORCE_DISCONNECT;
	struct nlattr *tla = info->attrs[DRBD_NLA_DISCONNECT_PARMS];
	struct nlattr *ntb[DRBD_A_DISCONNECT_PARMS_FORCE_DISCONNECT + 1];
	struct nlattr *nla;
	int err = 0;

	if (ret_nested_attribute_table)
		*ret_nested_attribute_table = NULL;
	if (!tla)
		return -ENOMSG;
	err = nla_parse_nested(ntb, maxtype, tla, drbd_disconnect_parms_nl_policy);
	if (err)
		return err;

	nla = ntb[DRBD_A_DISCONNECT_PARMS_FORCE_DISCONNECT];
	if (nla && s)
		s->force_disconnect = nla_get_u8(nla);

	if (ret_nested_attribute_table && (!err || err == -ENOMSG))
		memcpy(ret_nested_attribute_table, ntb, sizeof(ntb));
	return err;
}

int disconnect_parms_from_attrs(struct disconnect_parms *s,
				struct genl_info *info)
{
	return __disconnect_parms_from_attrs(s, NULL, info);
}

int disconnect_parms_ntb_from_attrs(
			struct nlattr ***ret_nested_attribute_table,
			struct genl_info *info)
{
	return __disconnect_parms_from_attrs(NULL, ret_nested_attribute_table, info);
}

static int __detach_parms_from_attrs(struct detach_parms *s,
		struct nlattr ***ret_nested_attribute_table,
		struct genl_info *info)
{
	const int maxtype = DRBD_A_DETACH_PARMS_INTENTIONAL_DISKLESS_DETACH;
	struct nlattr *tla = info->attrs[DRBD_NLA_DETACH_PARMS];
	struct nlattr *ntb[DRBD_A_DETACH_PARMS_INTENTIONAL_DISKLESS_DETACH + 1];
	struct nlattr *nla;
	int err = 0;

	if (ret_nested_attribute_table)
		*ret_nested_attribute_table = NULL;
	if (!tla)
		return -ENOMSG;
	err = nla_parse_nested(ntb, maxtype, tla, drbd_detach_parms_nl_policy);
	if (err)
		return err;

	nla = ntb[DRBD_A_DETACH_PARMS_FORCE_DETACH];
	if (nla && s)
		s->force_detach = nla_get_u8(nla);

	nla = ntb[DRBD_A_DETACH_PARMS_INTENTIONAL_DISKLESS_DETACH];
	if (nla && s)
		s->intentional_diskless_detach = nla_get_u8(nla);

	if (ret_nested_attribute_table && (!err || err == -ENOMSG))
		memcpy(ret_nested_attribute_table, ntb, sizeof(ntb));
	return err;
}

int detach_parms_from_attrs(struct detach_parms *s,
				struct genl_info *info)
{
	return __detach_parms_from_attrs(s, NULL, info);
}

int detach_parms_ntb_from_attrs(
			struct nlattr ***ret_nested_attribute_table,
			struct genl_info *info)
{
	return __detach_parms_from_attrs(NULL, ret_nested_attribute_table, info);
}

static int __device_conf_from_attrs(struct device_conf *s,
		struct nlattr ***ret_nested_attribute_table,
		struct genl_info *info)
{
	const int maxtype = DRBD_A_DEVICE_CONF_DISCARD_GRANULARITY;
	struct nlattr *tla = info->attrs[DRBD_NLA_DEVICE_CONF];
	struct nlattr *ntb[DRBD_A_DEVICE_CONF_DISCARD_GRANULARITY + 1];
	struct nlattr *nla;
	int err = 0;

	if (ret_nested_attribute_table)
		*ret_nested_attribute_table = NULL;
	if (!tla)
		return -ENOMSG;
	err = nla_parse_nested(ntb, maxtype, tla, drbd_device_conf_nl_policy);
	if (err)
		return err;

	nla = ntb[DRBD_A_DEVICE_CONF_MAX_BIO_SIZE];
	if (nla && s)
		s->max_bio_size = nla_get_u32(nla);

	nla = ntb[DRBD_A_DEVICE_CONF_INTENTIONAL_DISKLESS];
	if (nla && s)
		s->intentional_diskless = nla_get_u8(nla);

	nla = ntb[DRBD_A_DEVICE_CONF_BLOCK_SIZE];
	if (nla && s)
		s->block_size = nla_get_u32(nla);

	nla = ntb[DRBD_A_DEVICE_CONF_DISCARD_GRANULARITY];
	if (nla && s)
		s->discard_granularity = nla_get_u32(nla);

	if (ret_nested_attribute_table && (!err || err == -ENOMSG))
		memcpy(ret_nested_attribute_table, ntb, sizeof(ntb));
	return err;
}

int device_conf_from_attrs(struct device_conf *s,
				struct genl_info *info)
{
	return __device_conf_from_attrs(s, NULL, info);
}

int device_conf_ntb_from_attrs(
			struct nlattr ***ret_nested_attribute_table,
			struct genl_info *info)
{
	return __device_conf_from_attrs(NULL, ret_nested_attribute_table, info);
}

static int __resource_info_from_attrs(struct resource_info *s,
		struct nlattr ***ret_nested_attribute_table,
		struct genl_info *info)
{
	const int maxtype = DRBD_A_RESOURCE_INFO_RES_FAIL_IO;
	struct nlattr *tla = info->attrs[DRBD_NLA_RESOURCE_INFO];
	struct nlattr *ntb[DRBD_A_RESOURCE_INFO_RES_FAIL_IO + 1];
	struct nlattr *nla;
	int err = 0;

	if (ret_nested_attribute_table)
		*ret_nested_attribute_table = NULL;
	if (!tla)
		return -ENOMSG;
	err = nla_parse_nested(ntb, maxtype, tla, drbd_resource_info_nl_policy);
	if (err)
		return err;

	nla = ntb[DRBD_A_RESOURCE_INFO_RES_ROLE];
	if (nla && s)
		s->res_role = nla_get_u32(nla);

	nla = ntb[DRBD_A_RESOURCE_INFO_RES_SUSP];
	if (nla && s)
		s->res_susp = nla_get_u8(nla);

	nla = ntb[DRBD_A_RESOURCE_INFO_RES_SUSP_NOD];
	if (nla && s)
		s->res_susp_nod = nla_get_u8(nla);

	nla = ntb[DRBD_A_RESOURCE_INFO_RES_SUSP_FEN];
	if (nla && s)
		s->res_susp_fen = nla_get_u8(nla);

	nla = ntb[DRBD_A_RESOURCE_INFO_RES_SUSP_QUORUM];
	if (nla && s)
		s->res_susp_quorum = nla_get_u8(nla);

	nla = ntb[DRBD_A_RESOURCE_INFO_RES_FAIL_IO];
	if (nla && s)
		s->res_fail_io = nla_get_u8(nla);

	if (ret_nested_attribute_table && (!err || err == -ENOMSG))
		memcpy(ret_nested_attribute_table, ntb, sizeof(ntb));
	return err;
}

int resource_info_from_attrs(struct resource_info *s,
				struct genl_info *info)
{
	return __resource_info_from_attrs(s, NULL, info);
}

int resource_info_ntb_from_attrs(
			struct nlattr ***ret_nested_attribute_table,
			struct genl_info *info)
{
	return __resource_info_from_attrs(NULL, ret_nested_attribute_table, info);
}

static int __device_info_from_attrs(struct device_info *s,
		struct nlattr ***ret_nested_attribute_table,
		struct genl_info *info)
{
	const int maxtype = DRBD_A_DEVICE_INFO_DEV_IS_OPEN;
	struct nlattr *tla = info->attrs[DRBD_NLA_DEVICE_INFO];
	struct nlattr *ntb[DRBD_A_DEVICE_INFO_DEV_IS_OPEN + 1];
	struct nlattr *nla;
	int err = 0;

	if (ret_nested_attribute_table)
		*ret_nested_attribute_table = NULL;
	if (!tla)
		return -ENOMSG;
	err = nla_parse_nested(ntb, maxtype, tla, drbd_device_info_nl_policy);
	if (err)
		return err;

	nla = ntb[DRBD_A_DEVICE_INFO_DEV_DISK_STATE];
	if (nla && s)
		s->dev_disk_state = nla_get_u32(nla);

	nla = ntb[DRBD_A_DEVICE_INFO_IS_INTENTIONAL_DISKLESS];
	if (nla && s)
		s->is_intentional_diskless = nla_get_u8(nla);

	nla = ntb[DRBD_A_DEVICE_INFO_DEV_HAS_QUORUM];
	if (nla && s)
		s->dev_has_quorum = nla_get_u8(nla);

	nla = ntb[DRBD_A_DEVICE_INFO_DEV_IS_OPEN];
	if (nla && s)
		s->dev_is_open = nla_get_u8(nla);

	nla = ntb[DRBD_A_DEVICE_INFO_BACKING_DEV_PATH];
	if (nla && s)
		s->backing_dev_path_len = nla_strlcpy(s->backing_dev_path, nla, 128);

	if (ret_nested_attribute_table && (!err || err == -ENOMSG))
		memcpy(ret_nested_attribute_table, ntb, sizeof(ntb));
	return err;
}

int device_info_from_attrs(struct device_info *s,
				struct genl_info *info)
{
	return __device_info_from_attrs(s, NULL, info);
}

int device_info_ntb_from_attrs(
			struct nlattr ***ret_nested_attribute_table,
			struct genl_info *info)
{
	return __device_info_from_attrs(NULL, ret_nested_attribute_table, info);
}

static int __connection_info_from_attrs(struct connection_info *s,
		struct nlattr ***ret_nested_attribute_table,
		struct genl_info *info)
{
	const int maxtype = DRBD_A_CONNECTION_INFO_CONN_ROLE;
	struct nlattr *tla = info->attrs[DRBD_NLA_CONNECTION_INFO];
	struct nlattr *ntb[DRBD_A_CONNECTION_INFO_CONN_ROLE + 1];
	struct nlattr *nla;
	int err = 0;

	if (ret_nested_attribute_table)
		*ret_nested_attribute_table = NULL;
	if (!tla)
		return -ENOMSG;
	err = nla_parse_nested(ntb, maxtype, tla, drbd_connection_info_nl_policy);
	if (err)
		return err;

	nla = ntb[DRBD_A_CONNECTION_INFO_CONN_CONNECTION_STATE];
	if (nla && s)
		s->conn_connection_state = nla_get_u32(nla);

	nla = ntb[DRBD_A_CONNECTION_INFO_CONN_ROLE];
	if (nla && s)
		s->conn_role = nla_get_u32(nla);

	if (ret_nested_attribute_table && (!err || err == -ENOMSG))
		memcpy(ret_nested_attribute_table, ntb, sizeof(ntb));
	return err;
}

int connection_info_from_attrs(struct connection_info *s,
				struct genl_info *info)
{
	return __connection_info_from_attrs(s, NULL, info);
}

int connection_info_ntb_from_attrs(
			struct nlattr ***ret_nested_attribute_table,
			struct genl_info *info)
{
	return __connection_info_from_attrs(NULL, ret_nested_attribute_table, info);
}

static int __peer_device_info_from_attrs(struct peer_device_info *s,
		struct nlattr ***ret_nested_attribute_table,
		struct genl_info *info)
{
	const int maxtype = DRBD_A_PEER_DEVICE_INFO_PEER_RESYNC_SUSP_MAX_PARALLEL;
	struct nlattr *tla = info->attrs[DRBD_NLA_PEER_DEVICE_INFO];
	struct nlattr *ntb[DRBD_A_PEER_DEVICE_INFO_PEER_RESYNC_SUSP_MAX_PARALLEL + 1];
	struct nlattr *nla;
	int err = 0;

	if (ret_nested_attribute_table)
		*ret_nested_attribute_table = NULL;
	if (!tla)
		return -ENOMSG;
	err = nla_parse_nested(ntb, maxtype, tla, drbd_peer_device_info_nl_policy);
	if (err)
		return err;

	nla = ntb[DRBD_A_PEER_DEVICE_INFO_PEER_REPL_STATE];
	if (nla && s)
		s->peer_repl_state = nla_get_u32(nla);

	nla = ntb[DRBD_A_PEER_DEVICE_INFO_PEER_DISK_STATE];
	if (nla && s)
		s->peer_disk_state = nla_get_u32(nla);

	nla = ntb[DRBD_A_PEER_DEVICE_INFO_PEER_RESYNC_SUSP_USER];
	if (nla && s)
		s->peer_resync_susp_user = nla_get_u32(nla);

	nla = ntb[DRBD_A_PEER_DEVICE_INFO_PEER_RESYNC_SUSP_PEER];
	if (nla && s)
		s->peer_resync_susp_peer = nla_get_u32(nla);

	nla = ntb[DRBD_A_PEER_DEVICE_INFO_PEER_RESYNC_SUSP_DEPENDENCY];
	if (nla && s)
		s->peer_resync_susp_dependency = nla_get_u32(nla);

	nla = ntb[DRBD_A_PEER_DEVICE_INFO_PEER_IS_INTENTIONAL_DISKLESS];
	if (nla && s)
		s->peer_is_intentional_diskless = nla_get_u8(nla);

	nla = ntb[DRBD_A_PEER_DEVICE_INFO_PEER_RESYNC_SUSP_MAX_PARALLEL];
	if (nla && s)
		s->peer_resync_susp_max_parallel = nla_get_u32(nla);

	if (ret_nested_attribute_table && (!err || err == -ENOMSG))
		memcpy(ret_nested_attribute_table, ntb, sizeof(ntb));
	return err;
}

int peer_device_info_from_attrs(struct peer_device_info *s,
				struct genl_info *info)
{
	return __peer_device_info_from_attrs(s, NULL, info);
}

int peer_device_info_ntb_from_attrs(
			struct nlattr ***ret_nested_attribute_table,
			struct genl_info *info)
{
	return __peer_device_info_from_attrs(NULL, ret_nested_attribute_table, info);
}

static int __resource_statistics_from_attrs(struct resource_statistics *s,
		struct nlattr ***ret_nested_attribute_table,
		struct genl_info *info)
{
	const int maxtype = DRBD_A_RESOURCE_STATISTICS_RES_STAT_WRITE_ORDERING;
	struct nlattr *tla = info->attrs[DRBD_NLA_RESOURCE_STATISTICS];
	struct nlattr *ntb[DRBD_A_RESOURCE_STATISTICS_RES_STAT_WRITE_ORDERING + 1];
	struct nlattr *nla;
	int err = 0;

	if (ret_nested_attribute_table)
		*ret_nested_attribute_table = NULL;
	if (!tla)
		return -ENOMSG;
	err = nla_parse_nested(ntb, maxtype, tla, drbd_resource_statistics_nl_policy);
	if (err)
		return err;

	nla = ntb[DRBD_A_RESOURCE_STATISTICS_RES_STAT_WRITE_ORDERING];
	if (nla && s)
		s->res_stat_write_ordering = nla_get_u32(nla);

	if (ret_nested_attribute_table && (!err || err == -ENOMSG))
		memcpy(ret_nested_attribute_table, ntb, sizeof(ntb));
	return err;
}

int resource_statistics_from_attrs(struct resource_statistics *s,
				struct genl_info *info)
{
	return __resource_statistics_from_attrs(s, NULL, info);
}

int resource_statistics_ntb_from_attrs(
			struct nlattr ***ret_nested_attribute_table,
			struct genl_info *info)
{
	return __resource_statistics_from_attrs(NULL, ret_nested_attribute_table, info);
}

static int __device_statistics_from_attrs(struct device_statistics *s,
		struct nlattr ***ret_nested_attribute_table,
		struct genl_info *info)
{
	const int maxtype = DRBD_A_DEVICE_STATISTICS_HISTORY_UUIDS;
	struct nlattr *tla = info->attrs[DRBD_NLA_DEVICE_STATISTICS];
	struct nlattr *ntb[DRBD_A_DEVICE_STATISTICS_HISTORY_UUIDS + 1];
	struct nlattr *nla;
	int err = 0;

	if (ret_nested_attribute_table)
		*ret_nested_attribute_table = NULL;
	if (!tla)
		return -ENOMSG;
	err = nla_parse_nested(ntb, maxtype, tla, drbd_device_statistics_nl_policy);
	if (err)
		return err;

	nla = ntb[DRBD_A_DEVICE_STATISTICS_DEV_SIZE];
	if (nla && s)
		s->dev_size = nla_get_u64(nla);

	nla = ntb[DRBD_A_DEVICE_STATISTICS_DEV_READ];
	if (nla && s)
		s->dev_read = nla_get_u64(nla);

	nla = ntb[DRBD_A_DEVICE_STATISTICS_DEV_WRITE];
	if (nla && s)
		s->dev_write = nla_get_u64(nla);

	nla = ntb[DRBD_A_DEVICE_STATISTICS_DEV_AL_WRITES];
	if (nla && s)
		s->dev_al_writes = nla_get_u64(nla);

	nla = ntb[DRBD_A_DEVICE_STATISTICS_DEV_BM_WRITES];
	if (nla && s)
		s->dev_bm_writes = nla_get_u64(nla);

	nla = ntb[DRBD_A_DEVICE_STATISTICS_DEV_UPPER_PENDING];
	if (nla && s)
		s->dev_upper_pending = nla_get_u32(nla);

	nla = ntb[DRBD_A_DEVICE_STATISTICS_DEV_LOWER_PENDING];
	if (nla && s)
		s->dev_lower_pending = nla_get_u32(nla);

	nla = ntb[DRBD_A_DEVICE_STATISTICS_DEV_UPPER_BLOCKED];
	if (nla && s)
		s->dev_upper_blocked = nla_get_u8(nla);

	nla = ntb[DRBD_A_DEVICE_STATISTICS_DEV_LOWER_BLOCKED];
	if (nla && s)
		s->dev_lower_blocked = nla_get_u8(nla);

	nla = ntb[DRBD_A_DEVICE_STATISTICS_DEV_AL_SUSPENDED];
	if (nla && s)
		s->dev_al_suspended = nla_get_u8(nla);

	nla = ntb[DRBD_A_DEVICE_STATISTICS_DEV_EXPOSED_DATA_UUID];
	if (nla && s)
		s->dev_exposed_data_uuid = nla_get_u64(nla);

	nla = ntb[DRBD_A_DEVICE_STATISTICS_DEV_CURRENT_UUID];
	if (nla && s)
		s->dev_current_uuid = nla_get_u64(nla);

	nla = ntb[DRBD_A_DEVICE_STATISTICS_DEV_DISK_FLAGS];
	if (nla && s)
		s->dev_disk_flags = nla_get_u32(nla);

	nla = ntb[DRBD_A_DEVICE_STATISTICS_HISTORY_UUIDS];
	if (nla && s)
		s->history_uuids_len = nla_memcpy(s->history_uuids, nla, HISTORY_UUIDS_SIZE);

	if (ret_nested_attribute_table && (!err || err == -ENOMSG))
		memcpy(ret_nested_attribute_table, ntb, sizeof(ntb));
	return err;
}

int device_statistics_from_attrs(struct device_statistics *s,
				struct genl_info *info)
{
	return __device_statistics_from_attrs(s, NULL, info);
}

int device_statistics_ntb_from_attrs(
			struct nlattr ***ret_nested_attribute_table,
			struct genl_info *info)
{
	return __device_statistics_from_attrs(NULL, ret_nested_attribute_table, info);
}

static int __connection_statistics_from_attrs(struct connection_statistics *s,
		struct nlattr ***ret_nested_attribute_table,
		struct genl_info *info)
{
	const int maxtype = DRBD_A_CONNECTION_STATISTICS_RS_IN_FLIGHT;
	struct nlattr *tla = info->attrs[DRBD_NLA_CONNECTION_STATISTICS];
	struct nlattr *ntb[DRBD_A_CONNECTION_STATISTICS_RS_IN_FLIGHT + 1];
	struct nlattr *nla;
	int err = 0;

	if (ret_nested_attribute_table)
		*ret_nested_attribute_table = NULL;
	if (!tla)
		return -ENOMSG;
	err = nla_parse_nested(ntb, maxtype, tla, drbd_connection_statistics_nl_policy);
	if (err)
		return err;

	nla = ntb[DRBD_A_CONNECTION_STATISTICS_CONN_CONGESTED];
	if (nla && s)
		s->conn_congested = nla_get_u8(nla);

	nla = ntb[DRBD_A_CONNECTION_STATISTICS_AP_IN_FLIGHT];
	if (nla && s)
		s->ap_in_flight = nla_get_u64(nla);

	nla = ntb[DRBD_A_CONNECTION_STATISTICS_RS_IN_FLIGHT];
	if (nla && s)
		s->rs_in_flight = nla_get_u64(nla);

	if (ret_nested_attribute_table && (!err || err == -ENOMSG))
		memcpy(ret_nested_attribute_table, ntb, sizeof(ntb));
	return err;
}

int connection_statistics_from_attrs(struct connection_statistics *s,
				struct genl_info *info)
{
	return __connection_statistics_from_attrs(s, NULL, info);
}

int connection_statistics_ntb_from_attrs(
			struct nlattr ***ret_nested_attribute_table,
			struct genl_info *info)
{
	return __connection_statistics_from_attrs(NULL, ret_nested_attribute_table, info);
}

static int __peer_device_statistics_from_attrs(struct peer_device_statistics *s,
		struct nlattr ***ret_nested_attribute_table,
		struct genl_info *info)
{
	const int maxtype = DRBD_A_PEER_DEVICE_STATISTICS_PEER_DEV_UUID_FLAGS;
	struct nlattr *tla = info->attrs[DRBD_NLA_PEER_DEVICE_STATISTICS];
	struct nlattr *ntb[DRBD_A_PEER_DEVICE_STATISTICS_PEER_DEV_UUID_FLAGS + 1];
	struct nlattr *nla;
	int err = 0;

	if (ret_nested_attribute_table)
		*ret_nested_attribute_table = NULL;
	if (!tla)
		return -ENOMSG;
	err = nla_parse_nested(ntb, maxtype, tla, drbd_peer_device_statistics_nl_policy);
	if (err)
		return err;

	nla = ntb[DRBD_A_PEER_DEVICE_STATISTICS_PEER_DEV_RECEIVED];
	if (nla && s)
		s->peer_dev_received = nla_get_u64(nla);

	nla = ntb[DRBD_A_PEER_DEVICE_STATISTICS_PEER_DEV_SENT];
	if (nla && s)
		s->peer_dev_sent = nla_get_u64(nla);

	nla = ntb[DRBD_A_PEER_DEVICE_STATISTICS_PEER_DEV_PENDING];
	if (nla && s)
		s->peer_dev_pending = nla_get_u32(nla);

	nla = ntb[DRBD_A_PEER_DEVICE_STATISTICS_PEER_DEV_UNACKED];
	if (nla && s)
		s->peer_dev_unacked = nla_get_u32(nla);

	nla = ntb[DRBD_A_PEER_DEVICE_STATISTICS_PEER_DEV_OUT_OF_SYNC];
	if (nla && s)
		s->peer_dev_out_of_sync = nla_get_u64(nla);

	nla = ntb[DRBD_A_PEER_DEVICE_STATISTICS_PEER_DEV_RESYNC_FAILED];
	if (nla && s)
		s->peer_dev_resync_failed = nla_get_u64(nla);

	nla = ntb[DRBD_A_PEER_DEVICE_STATISTICS_PEER_DEV_BITMAP_UUID];
	if (nla && s)
		s->peer_dev_bitmap_uuid = nla_get_u64(nla);

	nla = ntb[DRBD_A_PEER_DEVICE_STATISTICS_PEER_DEV_FLAGS];
	if (nla && s)
		s->peer_dev_flags = nla_get_u32(nla);

	nla = ntb[DRBD_A_PEER_DEVICE_STATISTICS_PEER_DEV_RS_TOTAL];
	if (nla && s)
		s->peer_dev_rs_total = nla_get_u64(nla);

	nla = ntb[DRBD_A_PEER_DEVICE_STATISTICS_PEER_DEV_OV_START_SECTOR];
	if (nla && s)
		s->peer_dev_ov_start_sector = nla_get_u64(nla);

	nla = ntb[DRBD_A_PEER_DEVICE_STATISTICS_PEER_DEV_OV_STOP_SECTOR];
	if (nla && s)
		s->peer_dev_ov_stop_sector = nla_get_u64(nla);

	nla = ntb[DRBD_A_PEER_DEVICE_STATISTICS_PEER_DEV_OV_POSITION];
	if (nla && s)
		s->peer_dev_ov_position = nla_get_u64(nla);

	nla = ntb[DRBD_A_PEER_DEVICE_STATISTICS_PEER_DEV_OV_LEFT];
	if (nla && s)
		s->peer_dev_ov_left = nla_get_u64(nla);

	nla = ntb[DRBD_A_PEER_DEVICE_STATISTICS_PEER_DEV_OV_SKIPPED];
	if (nla && s)
		s->peer_dev_ov_skipped = nla_get_u64(nla);

	nla = ntb[DRBD_A_PEER_DEVICE_STATISTICS_PEER_DEV_RS_SAME_CSUM];
	if (nla && s)
		s->peer_dev_rs_same_csum = nla_get_u64(nla);

	nla = ntb[DRBD_A_PEER_DEVICE_STATISTICS_PEER_DEV_RS_DT_START_MS];
	if (nla && s)
		s->peer_dev_rs_dt_start_ms = nla_get_u64(nla);

	nla = ntb[DRBD_A_PEER_DEVICE_STATISTICS_PEER_DEV_RS_PAUSED_MS];
	if (nla && s)
		s->peer_dev_rs_paused_ms = nla_get_u64(nla);

	nla = ntb[DRBD_A_PEER_DEVICE_STATISTICS_PEER_DEV_RS_DT0_MS];
	if (nla && s)
		s->peer_dev_rs_dt0_ms = nla_get_u64(nla);

	nla = ntb[DRBD_A_PEER_DEVICE_STATISTICS_PEER_DEV_RS_DB0_SECTORS];
	if (nla && s)
		s->peer_dev_rs_db0_sectors = nla_get_u64(nla);

	nla = ntb[DRBD_A_PEER_DEVICE_STATISTICS_PEER_DEV_RS_DT1_MS];
	if (nla && s)
		s->peer_dev_rs_dt1_ms = nla_get_u64(nla);

	nla = ntb[DRBD_A_PEER_DEVICE_STATISTICS_PEER_DEV_RS_DB1_SECTORS];
	if (nla && s)
		s->peer_dev_rs_db1_sectors = nla_get_u64(nla);

	nla = ntb[DRBD_A_PEER_DEVICE_STATISTICS_PEER_DEV_RS_C_SYNC_RATE];
	if (nla && s)
		s->peer_dev_rs_c_sync_rate = nla_get_u32(nla);

	nla = ntb[DRBD_A_PEER_DEVICE_STATISTICS_PEER_DEV_UUID_FLAGS];
	if (nla && s)
		s->peer_dev_uuid_flags = nla_get_u64(nla);

	if (ret_nested_attribute_table && (!err || err == -ENOMSG))
		memcpy(ret_nested_attribute_table, ntb, sizeof(ntb));
	return err;
}

int peer_device_statistics_from_attrs(struct peer_device_statistics *s,
				struct genl_info *info)
{
	return __peer_device_statistics_from_attrs(s, NULL, info);
}

int peer_device_statistics_ntb_from_attrs(
			struct nlattr ***ret_nested_attribute_table,
			struct genl_info *info)
{
	return __peer_device_statistics_from_attrs(NULL, ret_nested_attribute_table, info);
}

static int __drbd_notification_header_from_attrs(struct drbd_notification_header *s,
		struct nlattr ***ret_nested_attribute_table,
		struct genl_info *info)
{
	const int maxtype = DRBD_A_DRBD_NOTIFICATION_HEADER_NH_TYPE;
	struct nlattr *tla = info->attrs[DRBD_NLA_NOTIFICATION_HEADER];
	struct nlattr *ntb[DRBD_A_DRBD_NOTIFICATION_HEADER_NH_TYPE + 1];
	struct nlattr *nla;
	int err = 0;

	if (ret_nested_attribute_table)
		*ret_nested_attribute_table = NULL;
	if (!tla)
		return -ENOMSG;
	err = nla_parse_nested(ntb, maxtype, tla, drbd_drbd_notification_header_nl_policy);
	if (err)
		return err;

	nla = ntb[DRBD_A_DRBD_NOTIFICATION_HEADER_NH_TYPE];
	if (nla && s)
		s->nh_type = nla_get_u32(nla);

	if (ret_nested_attribute_table && (!err || err == -ENOMSG))
		memcpy(ret_nested_attribute_table, ntb, sizeof(ntb));
	return err;
}

int drbd_notification_header_from_attrs(struct drbd_notification_header *s,
				struct genl_info *info)
{
	return __drbd_notification_header_from_attrs(s, NULL, info);
}

int drbd_notification_header_ntb_from_attrs(
			struct nlattr ***ret_nested_attribute_table,
			struct genl_info *info)
{
	return __drbd_notification_header_from_attrs(NULL, ret_nested_attribute_table, info);
}

static int __drbd_helper_info_from_attrs(struct drbd_helper_info *s,
		struct nlattr ***ret_nested_attribute_table,
		struct genl_info *info)
{
	const int maxtype = DRBD_A_DRBD_HELPER_INFO_HELPER_STATUS;
	struct nlattr *tla = info->attrs[DRBD_NLA_HELPER];
	struct nlattr *ntb[DRBD_A_DRBD_HELPER_INFO_HELPER_STATUS + 1];
	struct nlattr *nla;
	int err = 0;

	if (ret_nested_attribute_table)
		*ret_nested_attribute_table = NULL;
	if (!tla)
		return -ENOMSG;
	err = nla_parse_nested(ntb, maxtype, tla, drbd_drbd_helper_info_nl_policy);
	if (err)
		return err;

	nla = ntb[DRBD_A_DRBD_HELPER_INFO_HELPER_NAME];
	if (nla && s)
		s->helper_name_len = nla_strlcpy(s->helper_name, nla, 32);

	nla = ntb[DRBD_A_DRBD_HELPER_INFO_HELPER_STATUS];
	if (nla && s)
		s->helper_status = nla_get_u32(nla);

	if (ret_nested_attribute_table && (!err || err == -ENOMSG))
		memcpy(ret_nested_attribute_table, ntb, sizeof(ntb));
	return err;
}

int drbd_helper_info_from_attrs(struct drbd_helper_info *s,
				struct genl_info *info)
{
	return __drbd_helper_info_from_attrs(s, NULL, info);
}

int drbd_helper_info_ntb_from_attrs(
			struct nlattr ***ret_nested_attribute_table,
			struct genl_info *info)
{
	return __drbd_helper_info_from_attrs(NULL, ret_nested_attribute_table, info);
}

static int __invalidate_parms_from_attrs(struct invalidate_parms *s,
		struct nlattr ***ret_nested_attribute_table,
		struct genl_info *info)
{
	const int maxtype = DRBD_A_INVALIDATE_PARMS_RESET_BITMAP;
	struct nlattr *tla = info->attrs[DRBD_NLA_INVALIDATE_PARMS];
	struct nlattr *ntb[DRBD_A_INVALIDATE_PARMS_RESET_BITMAP + 1];
	struct nlattr *nla;
	int err = 0;

	if (ret_nested_attribute_table)
		*ret_nested_attribute_table = NULL;
	if (!tla)
		return -ENOMSG;
	err = nla_parse_nested(ntb, maxtype, tla, drbd_invalidate_parms_nl_policy);
	if (err)
		return err;

	nla = ntb[DRBD_A_INVALIDATE_PARMS_SYNC_FROM_PEER_NODE_ID];
	if (nla && s)
		s->sync_from_peer_node_id = nla_get_s32(nla);

	nla = ntb[DRBD_A_INVALIDATE_PARMS_RESET_BITMAP];
	if (nla && s)
		s->reset_bitmap = nla_get_u8(nla);

	if (ret_nested_attribute_table && (!err || err == -ENOMSG))
		memcpy(ret_nested_attribute_table, ntb, sizeof(ntb));
	return err;
}

int invalidate_parms_from_attrs(struct invalidate_parms *s,
				struct genl_info *info)
{
	return __invalidate_parms_from_attrs(s, NULL, info);
}

int invalidate_parms_ntb_from_attrs(
			struct nlattr ***ret_nested_attribute_table,
			struct genl_info *info)
{
	return __invalidate_parms_from_attrs(NULL, ret_nested_attribute_table, info);
}

static int __forget_peer_parms_from_attrs(struct forget_peer_parms *s,
		struct nlattr ***ret_nested_attribute_table,
		struct genl_info *info)
{
	const int maxtype = DRBD_A_FORGET_PEER_PARMS_FORGET_PEER_NODE_ID;
	struct nlattr *tla = info->attrs[DRBD_NLA_FORGET_PEER_PARMS];
	struct nlattr *ntb[DRBD_A_FORGET_PEER_PARMS_FORGET_PEER_NODE_ID + 1];
	struct nlattr *nla;
	int err = 0;

	if (ret_nested_attribute_table)
		*ret_nested_attribute_table = NULL;
	if (!tla)
		return -ENOMSG;
	err = nla_parse_nested(ntb, maxtype, tla, drbd_forget_peer_parms_nl_policy);
	if (err)
		return err;

	nla = ntb[DRBD_A_FORGET_PEER_PARMS_FORGET_PEER_NODE_ID];
	if (nla && s)
		s->forget_peer_node_id = nla_get_s32(nla);

	if (ret_nested_attribute_table && (!err || err == -ENOMSG))
		memcpy(ret_nested_attribute_table, ntb, sizeof(ntb));
	return err;
}

int forget_peer_parms_from_attrs(struct forget_peer_parms *s,
				struct genl_info *info)
{
	return __forget_peer_parms_from_attrs(s, NULL, info);
}

int forget_peer_parms_ntb_from_attrs(
			struct nlattr ***ret_nested_attribute_table,
			struct genl_info *info)
{
	return __forget_peer_parms_from_attrs(NULL, ret_nested_attribute_table, info);
}

static int __peer_device_conf_from_attrs(struct peer_device_conf *s,
		struct nlattr ***ret_nested_attribute_table,
		struct genl_info *info)
{
	const int maxtype = DRBD_A_PEER_DEVICE_CONF_PEER_TIEBREAKER;
	struct nlattr *tla = info->attrs[DRBD_NLA_PEER_DEVICE_OPTS];
	struct nlattr *ntb[DRBD_A_PEER_DEVICE_CONF_PEER_TIEBREAKER + 1];
	struct nlattr *nla;
	int err = 0;

	if (ret_nested_attribute_table)
		*ret_nested_attribute_table = NULL;
	if (!tla)
		return -ENOMSG;
	err = nla_parse_nested(ntb, maxtype, tla, drbd_peer_device_conf_nl_policy);
	if (err)
		return err;

	nla = ntb[DRBD_A_PEER_DEVICE_CONF_RESYNC_RATE];
	if (nla && s)
		s->resync_rate = nla_get_u32(nla);

	nla = ntb[DRBD_A_PEER_DEVICE_CONF_C_PLAN_AHEAD];
	if (nla && s)
		s->c_plan_ahead = nla_get_u32(nla);

	nla = ntb[DRBD_A_PEER_DEVICE_CONF_C_DELAY_TARGET];
	if (nla && s)
		s->c_delay_target = nla_get_u32(nla);

	nla = ntb[DRBD_A_PEER_DEVICE_CONF_C_FILL_TARGET];
	if (nla && s)
		s->c_fill_target = nla_get_u32(nla);

	nla = ntb[DRBD_A_PEER_DEVICE_CONF_C_MAX_RATE];
	if (nla && s)
		s->c_max_rate = nla_get_u32(nla);

	nla = ntb[DRBD_A_PEER_DEVICE_CONF_C_MIN_RATE];
	if (nla && s)
		s->c_min_rate = nla_get_u32(nla);

	nla = ntb[DRBD_A_PEER_DEVICE_CONF_BITMAP];
	if (nla && s)
		s->bitmap = nla_get_u8(nla);

	nla = ntb[DRBD_A_PEER_DEVICE_CONF_RESYNC_WITHOUT_REPLICATION];
	if (nla && s)
		s->resync_without_replication = nla_get_u8(nla);

	nla = ntb[DRBD_A_PEER_DEVICE_CONF_PEER_TIEBREAKER];
	if (nla && s)
		s->peer_tiebreaker = nla_get_u8(nla);

	if (ret_nested_attribute_table && (!err || err == -ENOMSG))
		memcpy(ret_nested_attribute_table, ntb, sizeof(ntb));
	return err;
}

int peer_device_conf_from_attrs(struct peer_device_conf *s,
				struct genl_info *info)
{
	return __peer_device_conf_from_attrs(s, NULL, info);
}

int peer_device_conf_ntb_from_attrs(
			struct nlattr ***ret_nested_attribute_table,
			struct genl_info *info)
{
	return __peer_device_conf_from_attrs(NULL, ret_nested_attribute_table, info);
}

static int __path_parms_from_attrs(struct path_parms *s,
		struct nlattr ***ret_nested_attribute_table,
		struct genl_info *info)
{
	const int maxtype = DRBD_A_PATH_PARMS_PEER_ADDR;
	struct nlattr *tla = info->attrs[DRBD_NLA_PATH_PARMS];
	struct nlattr *ntb[DRBD_A_PATH_PARMS_PEER_ADDR + 1];
	struct nlattr *nla;
	int err = 0;

	if (ret_nested_attribute_table)
		*ret_nested_attribute_table = NULL;
	if (!tla)
		return -ENOMSG;
	err = nla_parse_nested(ntb, maxtype, tla, drbd_path_parms_nl_policy);
	if (err)
		return err;

	nla = ntb[DRBD_A_PATH_PARMS_MY_ADDR];
	if (nla && s)
		s->my_addr_len = nla_memcpy(s->my_addr, nla, 128);

	nla = ntb[DRBD_A_PATH_PARMS_PEER_ADDR];
	if (nla && s)
		s->peer_addr_len = nla_memcpy(s->peer_addr, nla, 128);

	if (ret_nested_attribute_table && (!err || err == -ENOMSG))
		memcpy(ret_nested_attribute_table, ntb, sizeof(ntb));
	return err;
}

int path_parms_from_attrs(struct path_parms *s,
				struct genl_info *info)
{
	return __path_parms_from_attrs(s, NULL, info);
}

int path_parms_ntb_from_attrs(
			struct nlattr ***ret_nested_attribute_table,
			struct genl_info *info)
{
	return __path_parms_from_attrs(NULL, ret_nested_attribute_table, info);
}

static int __connect_parms_from_attrs(struct connect_parms *s,
		struct nlattr ***ret_nested_attribute_table,
		struct genl_info *info)
{
	const int maxtype = DRBD_A_CONNECT_PARMS_DISCARD_MY_DATA;
	struct nlattr *tla = info->attrs[DRBD_NLA_CONNECT_PARMS];
	struct nlattr *ntb[DRBD_A_CONNECT_PARMS_DISCARD_MY_DATA + 1];
	struct nlattr *nla;
	int err = 0;

	if (ret_nested_attribute_table)
		*ret_nested_attribute_table = NULL;
	if (!tla)
		return -ENOMSG;
	err = nla_parse_nested(ntb, maxtype, tla, drbd_connect_parms_nl_policy);
	if (err)
		return err;

	nla = ntb[DRBD_A_CONNECT_PARMS_TENTATIVE];
	if (nla && s)
		s->tentative = nla_get_u8(nla);

	nla = ntb[DRBD_A_CONNECT_PARMS_DISCARD_MY_DATA];
	if (nla && s)
		s->discard_my_data = nla_get_u8(nla);

	if (ret_nested_attribute_table && (!err || err == -ENOMSG))
		memcpy(ret_nested_attribute_table, ntb, sizeof(ntb));
	return err;
}

int connect_parms_from_attrs(struct connect_parms *s,
				struct genl_info *info)
{
	return __connect_parms_from_attrs(s, NULL, info);
}

int connect_parms_ntb_from_attrs(
			struct nlattr ***ret_nested_attribute_table,
			struct genl_info *info)
{
	return __connect_parms_from_attrs(NULL, ret_nested_attribute_table, info);
}

static int __drbd_path_info_from_attrs(struct drbd_path_info *s,
		struct nlattr ***ret_nested_attribute_table,
		struct genl_info *info)
{
	const int maxtype = DRBD_A_DRBD_PATH_INFO_PATH_ESTABLISHED;
	struct nlattr *tla = info->attrs[DRBD_NLA_PATH_INFO];
	struct nlattr *ntb[DRBD_A_DRBD_PATH_INFO_PATH_ESTABLISHED + 1];
	struct nlattr *nla;
	int err = 0;

	if (ret_nested_attribute_table)
		*ret_nested_attribute_table = NULL;
	if (!tla)
		return -ENOMSG;
	err = nla_parse_nested(ntb, maxtype, tla, drbd_drbd_path_info_nl_policy);
	if (err)
		return err;

	nla = ntb[DRBD_A_DRBD_PATH_INFO_PATH_ESTABLISHED];
	if (nla && s)
		s->path_established = nla_get_u8(nla);

	if (ret_nested_attribute_table && (!err || err == -ENOMSG))
		memcpy(ret_nested_attribute_table, ntb, sizeof(ntb));
	return err;
}

int drbd_path_info_from_attrs(struct drbd_path_info *s,
				struct genl_info *info)
{
	return __drbd_path_info_from_attrs(s, NULL, info);
}

int drbd_path_info_ntb_from_attrs(
			struct nlattr ***ret_nested_attribute_table,
			struct genl_info *info)
{
	return __drbd_path_info_from_attrs(NULL, ret_nested_attribute_table, info);
}

static int __rename_resource_parms_from_attrs(struct rename_resource_parms *s,
		struct nlattr ***ret_nested_attribute_table,
		struct genl_info *info)
{
	const int maxtype = DRBD_A_RENAME_RESOURCE_PARMS_NEW_RESOURCE_NAME;
	struct nlattr *tla = info->attrs[DRBD_NLA_RENAME_RESOURCE_PARMS];
	struct nlattr *ntb[DRBD_A_RENAME_RESOURCE_PARMS_NEW_RESOURCE_NAME + 1];
	struct nlattr *nla;
	int err = 0;

	if (ret_nested_attribute_table)
		*ret_nested_attribute_table = NULL;
	if (!tla)
		return -ENOMSG;
	err = nla_parse_nested(ntb, maxtype, tla, drbd_rename_resource_parms_nl_policy);
	if (err)
		return err;

	nla = ntb[DRBD_A_RENAME_RESOURCE_PARMS_NEW_RESOURCE_NAME];
	if (nla && s)
		s->new_resource_name_len = nla_strlcpy(s->new_resource_name, nla, 128);

	if (ret_nested_attribute_table && (!err || err == -ENOMSG))
		memcpy(ret_nested_attribute_table, ntb, sizeof(ntb));
	return err;
}

int rename_resource_parms_from_attrs(struct rename_resource_parms *s,
				struct genl_info *info)
{
	return __rename_resource_parms_from_attrs(s, NULL, info);
}

int rename_resource_parms_ntb_from_attrs(
			struct nlattr ***ret_nested_attribute_table,
			struct genl_info *info)
{
	return __rename_resource_parms_from_attrs(NULL, ret_nested_attribute_table, info);
}

static int __rename_resource_info_from_attrs(struct rename_resource_info *s,
		struct nlattr ***ret_nested_attribute_table,
		struct genl_info *info)
{
	const int maxtype = DRBD_A_RENAME_RESOURCE_INFO_RES_NEW_NAME;
	struct nlattr *tla = info->attrs[DRBD_NLA_RENAME_RESOURCE_INFO];
	struct nlattr *ntb[DRBD_A_RENAME_RESOURCE_INFO_RES_NEW_NAME + 1];
	struct nlattr *nla;
	int err = 0;

	if (ret_nested_attribute_table)
		*ret_nested_attribute_table = NULL;
	if (!tla)
		return -ENOMSG;
	err = nla_parse_nested(ntb, maxtype, tla, drbd_rename_resource_info_nl_policy);
	if (err)
		return err;

	nla = ntb[DRBD_A_RENAME_RESOURCE_INFO_RES_NEW_NAME];
	if (nla && s)
		s->res_new_name_len = nla_strlcpy(s->res_new_name, nla, 128);

	if (ret_nested_attribute_table && (!err || err == -ENOMSG))
		memcpy(ret_nested_attribute_table, ntb, sizeof(ntb));
	return err;
}

int rename_resource_info_from_attrs(struct rename_resource_info *s,
				struct genl_info *info)
{
	return __rename_resource_info_from_attrs(s, NULL, info);
}

int rename_resource_info_ntb_from_attrs(
			struct nlattr ***ret_nested_attribute_table,
			struct genl_info *info)
{
	return __rename_resource_info_from_attrs(NULL, ret_nested_attribute_table, info);
}

static int __invalidate_peer_parms_from_attrs(struct invalidate_peer_parms *s,
		struct nlattr ***ret_nested_attribute_table,
		struct genl_info *info)
{
	const int maxtype = DRBD_A_INVALIDATE_PEER_PARMS_P_RESET_BITMAP;
	struct nlattr *tla = info->attrs[DRBD_NLA_INVAL_PEER_PARAMS];
	struct nlattr *ntb[DRBD_A_INVALIDATE_PEER_PARMS_P_RESET_BITMAP + 1];
	struct nlattr *nla;
	int err = 0;

	if (ret_nested_attribute_table)
		*ret_nested_attribute_table = NULL;
	if (!tla)
		return -ENOMSG;
	err = nla_parse_nested(ntb, maxtype, tla, drbd_invalidate_peer_parms_nl_policy);
	if (err)
		return err;

	nla = ntb[DRBD_A_INVALIDATE_PEER_PARMS_P_RESET_BITMAP];
	if (nla && s)
		s->p_reset_bitmap = nla_get_u8(nla);

	if (ret_nested_attribute_table && (!err || err == -ENOMSG))
		memcpy(ret_nested_attribute_table, ntb, sizeof(ntb));
	return err;
}

int invalidate_peer_parms_from_attrs(struct invalidate_peer_parms *s,
				struct genl_info *info)
{
	return __invalidate_peer_parms_from_attrs(s, NULL, info);
}

int invalidate_peer_parms_ntb_from_attrs(
			struct nlattr ***ret_nested_attribute_table,
			struct genl_info *info)
{
	return __invalidate_peer_parms_from_attrs(NULL, ret_nested_attribute_table, info);
}

static int __suspend_io_parms_from_attrs(struct suspend_io_parms *s,
		struct nlattr ***ret_nested_attribute_table,
		struct genl_info *info)
{
	const int maxtype = DRBD_A_SUSPEND_IO_PARMS_BDEV_FREEZE;
	struct nlattr *tla = info->attrs[DRBD_NLA_SUSPEND_IO_PARAMS];
	struct nlattr *ntb[DRBD_A_SUSPEND_IO_PARMS_BDEV_FREEZE + 1];
	struct nlattr *nla;
	int err = 0;

	if (ret_nested_attribute_table)
		*ret_nested_attribute_table = NULL;
	if (!tla)
		return -ENOMSG;
	err = nla_parse_nested(ntb, maxtype, tla, drbd_suspend_io_parms_nl_policy);
	if (err)
		return err;

	nla = ntb[DRBD_A_SUSPEND_IO_PARMS_BDEV_FREEZE];
	if (nla && s)
		s->bdev_freeze = nla_get_u8(nla);

	if (ret_nested_attribute_table && (!err || err == -ENOMSG))
		memcpy(ret_nested_attribute_table, ntb, sizeof(ntb));
	return err;
}

int suspend_io_parms_from_attrs(struct suspend_io_parms *s,
				struct genl_info *info)
{
	return __suspend_io_parms_from_attrs(s, NULL, info);
}

int suspend_io_parms_ntb_from_attrs(
			struct nlattr ***ret_nested_attribute_table,
			struct genl_info *info)
{
	return __suspend_io_parms_from_attrs(NULL, ret_nested_attribute_table, info);
}

void set_drbd_cfg_context_defaults(struct drbd_cfg_context *x)
{
	memset(x->ctx_conn_name, 0, sizeof(x->ctx_conn_name));
	x->ctx_conn_name_len = 0;
}

void set_disk_conf_defaults(struct disk_conf *x)
{
	x->on_io_error = DRBD_ON_IO_ERROR_DEF;
	x->resync_after = DRBD_MINOR_NUMBER_DEF;
	x->al_extents = DRBD_AL_EXTENTS_DEF;
	x->disk_barrier = DRBD_DISK_BARRIER_DEF;
	x->disk_flushes = DRBD_DISK_FLUSHES_DEF;
	x->disk_drain = DRBD_DISK_DRAIN_DEF;
	x->md_flushes = DRBD_MD_FLUSHES_DEF;
	x->disk_timeout = DRBD_DISK_TIMEOUT_DEF;
	x->read_balancing = DRBD_READ_BALANCING_DEF;
	x->unplug_watermark = DRBD_UNPLUG_WATERMARK_DEF;
	x->rs_discard_granularity = DRBD_RS_DISCARD_GRANULARITY_DEF;
	x->al_updates = DRBD_AL_UPDATES_DEF;
	x->discard_zeroes_if_aligned = DRBD_DISCARD_ZEROES_IF_ALIGNED_DEF;
	x->disable_write_same = DRBD_DISABLE_WRITE_SAME_DEF;
	x->d_bitmap = DRBD_BITMAP_DEF;
}

void set_res_opts_defaults(struct res_opts *x)
{
	memset(x->cpu_mask, 0, sizeof(x->cpu_mask));
	x->cpu_mask_len = 0;
	x->on_no_data = DRBD_ON_NO_DATA_DEF;
	x->auto_promote = DRBD_AUTO_PROMOTE_DEF;
	x->peer_ack_window = DRBD_PEER_ACK_WINDOW_DEF;
	x->twopc_timeout = DRBD_TWOPC_TIMEOUT_DEF;
	x->twopc_retry_timeout = DRBD_TWOPC_RETRY_TIMEOUT_DEF;
	x->peer_ack_delay = DRBD_PEER_ACK_DELAY_DEF;
	x->auto_promote_timeout = DRBD_AUTO_PROMOTE_TIMEOUT_DEF;
	x->nr_requests = DRBD_NR_REQUESTS_DEF;
	x->quorum = DRBD_QUORUM_DEF;
	x->on_no_quorum = DRBD_ON_NO_QUORUM_DEF;
	x->quorum_min_redundancy = DRBD_QUORUM_DEF;
	x->on_susp_primary_outdated = DRBD_ON_SUSP_PRI_OUTD_DEF;
	x->drbd8_compat_mode = DRBD_DRBD8_COMPAT_MODE_DEF;
	x->explicit_drbd8_compat = DRBD_DRBD8_COMPAT_MODE_DEF;
}

void set_net_conf_defaults(struct net_conf *x)
{
	memset(x->shared_secret, 0, sizeof(x->shared_secret));
	x->shared_secret_len = 0;
	memset(x->cram_hmac_alg, 0, sizeof(x->cram_hmac_alg));
	x->cram_hmac_alg_len = 0;
	memset(x->integrity_alg, 0, sizeof(x->integrity_alg));
	x->integrity_alg_len = 0;
	memset(x->verify_alg, 0, sizeof(x->verify_alg));
	x->verify_alg_len = 0;
	memset(x->csums_alg, 0, sizeof(x->csums_alg));
	x->csums_alg_len = 0;
	x->wire_protocol = DRBD_PROTOCOL_DEF;
	x->connect_int = DRBD_CONNECT_INT_DEF;
	x->timeout = DRBD_TIMEOUT_DEF;
	x->ping_int = DRBD_PING_INT_DEF;
	x->ping_timeo = DRBD_PING_TIMEO_DEF;
	x->sndbuf_size = DRBD_SNDBUF_SIZE_DEF;
	x->rcvbuf_size = DRBD_RCVBUF_SIZE_DEF;
	x->ko_count = DRBD_KO_COUNT_DEF;
	x->max_epoch_size = DRBD_MAX_EPOCH_SIZE_DEF;
	x->after_sb_0p = DRBD_AFTER_SB_0P_DEF;
	x->after_sb_1p = DRBD_AFTER_SB_1P_DEF;
	x->after_sb_2p = DRBD_AFTER_SB_2P_DEF;
	x->rr_conflict = DRBD_RR_CONFLICT_DEF;
	x->on_congestion = DRBD_ON_CONGESTION_DEF;
	x->cong_fill = DRBD_CONG_FILL_DEF;
	x->cong_extents = DRBD_CONG_EXTENTS_DEF;
	x->two_primaries = DRBD_ALLOW_TWO_PRIMARIES_DEF;
	x->tcp_cork = DRBD_TCP_CORK_DEF;
	x->always_asbp = DRBD_ALWAYS_ASBP_DEF;
	x->use_rle = DRBD_USE_RLE_DEF;
	x->fencing_policy = DRBD_FENCING_DEF;
	memset(x->name, 0, sizeof(x->name));
	x->name_len = 0;
	x->csums_after_crash_only = DRBD_CSUMS_AFTER_CRASH_ONLY_DEF;
	x->sock_check_timeo = DRBD_SOCKET_CHECK_TIMEO_DEF;
	memset(x->transport_name, 0, sizeof(x->transport_name));
	x->transport_name_len = 0;
	x->max_buffers = DRBD_MAX_BUFFERS_DEF;
	x->allow_remote_read = DRBD_ALLOW_REMOTE_READ_DEF;
	x->tls = DRBD_TLS_DEF;
	x->tls_privkey = DRBD_TLS_PRIVKEY_DEF;
	x->tls_certificate = DRBD_TLS_CERTIFICATE_DEF;
	x->tls_keyring = DRBD_TLS_KEYRING_DEF;
	x->load_balance_paths = DRBD_LOAD_BALANCE_PATHS_DEF;
	x->rdma_ctrl_rcvbuf_size = DRBD_RDMA_CTRL_RCVBUF_SIZE_DEF;
	x->rdma_ctrl_sndbuf_size = DRBD_RDMA_CTRL_SNDBUF_SIZE_DEF;
}

void set_resize_parms_defaults(struct resize_parms *x)
{
	x->al_stripes = DRBD_AL_STRIPES_DEF;
	x->al_stripe_size = DRBD_AL_STRIPE_SIZE_DEF;
}

void set_detach_parms_defaults(struct detach_parms *x)
{
	x->intentional_diskless_detach = DRBD_DISK_DISKLESS_DEF;
}

void set_device_conf_defaults(struct device_conf *x)
{
	x->max_bio_size = DRBD_MAX_BIO_SIZE_DEF;
	x->intentional_diskless = DRBD_DISK_DISKLESS_DEF;
	x->block_size = DRBD_BLOCK_SIZE_DEF;
	x->discard_granularity = DRBD_DISCARD_GRANULARITY_DEF;
}

void set_invalidate_parms_defaults(struct invalidate_parms *x)
{
	x->sync_from_peer_node_id = DRBD_SYNC_FROM_NID_DEF;
	x->reset_bitmap = DRBD_INVALIDATE_RESET_BITMAP_DEF;
}

void set_forget_peer_parms_defaults(struct forget_peer_parms *x)
{
	x->forget_peer_node_id = DRBD_SYNC_FROM_NID_DEF;
}

void set_peer_device_conf_defaults(struct peer_device_conf *x)
{
	x->resync_rate = DRBD_RESYNC_RATE_DEF;
	x->c_plan_ahead = DRBD_C_PLAN_AHEAD_DEF;
	x->c_delay_target = DRBD_C_DELAY_TARGET_DEF;
	x->c_fill_target = DRBD_C_FILL_TARGET_DEF;
	x->c_max_rate = DRBD_C_MAX_RATE_DEF;
	x->c_min_rate = DRBD_C_MIN_RATE_DEF;
	x->bitmap = DRBD_BITMAP_DEF;
	x->resync_without_replication = DRBD_RESYNC_WITHOUT_REPLICATION_DEF;
	x->peer_tiebreaker = DRBD_PEER_TIEBREAKER_DEF;
}

void set_connect_parms_defaults(struct connect_parms *x)
{
	x->tentative = 0;
	x->discard_my_data = 0;
}

void set_invalidate_peer_parms_defaults(struct invalidate_peer_parms *x)
{
	x->p_reset_bitmap = DRBD_INVALIDATE_RESET_BITMAP_DEF;
}

void set_suspend_io_parms_defaults(struct suspend_io_parms *x)
{
	x->bdev_freeze = DRBD_SUSPEND_IO_BDEV_FREEZE_DEF;
}
