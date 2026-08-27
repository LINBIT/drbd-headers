/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause) */
/* Do not edit directly, auto-generated from: */
/*	drbd_genl_ynl.yaml */
/* YNL-GEN userspace header */
/* To regenerate run: tools/net/ynl/ynl-regen.sh */

#ifndef _LINUX_DRBD_GEN_USERSPACE_H
#define _LINUX_DRBD_GEN_USERSPACE_H

#include <linux/types.h>
#include "libgenl.h"

#include <uapi/linux/drbd_genl.h>
#include <linux/drbd.h>
#include <linux/drbd_limits.h>

/* Nested type policies */
extern const struct nla_policy drbd_connect_parms_nl_policy[DRBD_A_CONNECT_PARMS_DISCARD_MY_DATA + 1];
extern const struct nla_policy drbd_connection_info_nl_policy[DRBD_A_CONNECTION_INFO_CONN_ROLE + 1];
extern const struct nla_policy drbd_connection_statistics_nl_policy[DRBD_A_CONNECTION_STATISTICS_RS_IN_FLIGHT + 1];
extern const struct nla_policy drbd_detach_parms_nl_policy[DRBD_A_DETACH_PARMS_INTENTIONAL_DISKLESS_DETACH + 1];
extern const struct nla_policy drbd_device_conf_nl_policy[DRBD_A_DEVICE_CONF_DISCARD_GRANULARITY + 1];
extern const struct nla_policy drbd_device_info_nl_policy[DRBD_A_DEVICE_INFO_DEV_IS_OPEN + 1];
extern const struct nla_policy drbd_device_statistics_nl_policy[DRBD_A_DEVICE_STATISTICS_HISTORY_UUIDS + 1];
extern const struct nla_policy drbd_disconnect_parms_nl_policy[DRBD_A_DISCONNECT_PARMS_FORCE_DISCONNECT + 1];
extern const struct nla_policy drbd_disk_conf_nl_policy[DRBD_A_DISK_CONF_D_BITMAP + 1];
extern const struct nla_policy drbd_drbd_cfg_context_nl_policy[DRBD_A_DRBD_CFG_CONTEXT_CTX_PEER_NODE_ID + 1];
extern const struct nla_policy drbd_drbd_cfg_reply_nl_policy[DRBD_A_DRBD_CFG_REPLY_INFO_TEXT + 1];
extern const struct nla_policy drbd_drbd_helper_info_nl_policy[DRBD_A_DRBD_HELPER_INFO_HELPER_STATUS + 1];
extern const struct nla_policy drbd_drbd_notification_header_nl_policy[DRBD_A_DRBD_NOTIFICATION_HEADER_NH_TYPE + 1];
extern const struct nla_policy drbd_drbd_path_info_nl_policy[DRBD_A_DRBD_PATH_INFO_PATH_ESTABLISHED + 1];
extern const struct nla_policy drbd_forget_peer_parms_nl_policy[DRBD_A_FORGET_PEER_PARMS_FORGET_PEER_NODE_ID + 1];
extern const struct nla_policy drbd_invalidate_parms_nl_policy[DRBD_A_INVALIDATE_PARMS_RESET_BITMAP + 1];
extern const struct nla_policy drbd_invalidate_peer_parms_nl_policy[DRBD_A_INVALIDATE_PEER_PARMS_P_RESET_BITMAP + 1];
extern const struct nla_policy drbd_net_conf_nl_policy[DRBD_A_NET_CONF_RDMA_CTRL_SNDBUF_SIZE + 1];
extern const struct nla_policy drbd_new_c_uuid_parms_nl_policy[DRBD_A_NEW_C_UUID_PARMS_FORCE_RESYNC + 1];
extern const struct nla_policy drbd_path_parms_nl_policy[DRBD_A_PATH_PARMS_PEER_ADDR + 1];
extern const struct nla_policy drbd_peer_device_conf_nl_policy[DRBD_A_PEER_DEVICE_CONF_PEER_TIEBREAKER + 1];
extern const struct nla_policy drbd_peer_device_info_nl_policy[DRBD_A_PEER_DEVICE_INFO_PEER_RESYNC_SUSP_MAX_PARALLEL + 1];
extern const struct nla_policy drbd_peer_device_statistics_nl_policy[DRBD_A_PEER_DEVICE_STATISTICS_PEER_DEV_UUID_FLAGS + 1];
extern const struct nla_policy drbd_rename_resource_info_nl_policy[DRBD_A_RENAME_RESOURCE_INFO_RES_NEW_NAME + 1];
extern const struct nla_policy drbd_rename_resource_parms_nl_policy[DRBD_A_RENAME_RESOURCE_PARMS_NEW_RESOURCE_NAME + 1];
extern const struct nla_policy drbd_res_opts_nl_policy[DRBD_A_RES_OPTS_EXPLICIT_DRBD8_COMPAT + 1];
extern const struct nla_policy drbd_resize_parms_nl_policy[DRBD_A_RESIZE_PARMS_AL_STRIPE_SIZE + 1];
extern const struct nla_policy drbd_resource_info_nl_policy[DRBD_A_RESOURCE_INFO_RES_FAIL_IO + 1];
extern const struct nla_policy drbd_resource_statistics_nl_policy[DRBD_A_RESOURCE_STATISTICS_RES_STAT_WRITE_ORDERING + 1];
extern const struct nla_policy drbd_set_role_parms_nl_policy[DRBD_A_SET_ROLE_PARMS_FORCE + 1];
extern const struct nla_policy drbd_start_ov_parms_nl_policy[DRBD_A_START_OV_PARMS_OV_STOP_SECTOR + 1];
extern const struct nla_policy drbd_suspend_io_parms_nl_policy[DRBD_A_SUSPEND_IO_PARMS_BDEV_FREEZE + 1];
extern const struct nla_policy drbd_timeout_parms_nl_policy[DRBD_A_TIMEOUT_PARMS_TIMEOUT_TYPE + 1];

struct drbd_cfg_reply {
	char info_text[0];
	__u32 info_text_len;
};

struct drbd_cfg_context {
	__u32 ctx_peer_node_id;
	__u32 ctx_volume;
	char ctx_resource_name[128];
	__u32 ctx_resource_name_len;
	char ctx_my_addr[128];
	__u32 ctx_my_addr_len;
	char ctx_peer_addr[128];
	__u32 ctx_peer_addr_len;
	char ctx_conn_name[SHARED_SECRET_MAX];
	__u32 ctx_conn_name_len;
};

struct disk_conf {
	char backing_dev[128];
	__u32 backing_dev_len;
	char meta_dev[128];
	__u32 meta_dev_len;
	__s32 meta_dev_idx;
	__u64 disk_size;
	__u32 on_io_error;
	__s32 resync_after;
	__u32 al_extents;
	unsigned char disk_barrier;
	unsigned char disk_flushes;
	unsigned char disk_drain;
	unsigned char md_flushes;
	__u32 disk_timeout;
	__u32 read_balancing;
	__u32 unplug_watermark;
	__u32 rs_discard_granularity;
	unsigned char al_updates;
	unsigned char discard_zeroes_if_aligned;
	unsigned char disable_write_same;
	unsigned char d_bitmap;
};

struct res_opts {
	char cpu_mask[DRBD_CPU_MASK_SIZE];
	__u32 cpu_mask_len;
	__u32 on_no_data;
	unsigned char auto_promote;
	__u32 node_id;
	__u32 peer_ack_window;
	__u32 twopc_timeout;
	__u32 twopc_retry_timeout;
	__u32 peer_ack_delay;
	__u32 auto_promote_timeout;
	__u32 nr_requests;
	__s32 quorum;
	__u32 on_no_quorum;
	__s32 quorum_min_redundancy;
	__u32 on_susp_primary_outdated;
	unsigned char drbd8_compat_mode;
	unsigned char explicit_drbd8_compat;
};

struct net_conf {
	char shared_secret[SHARED_SECRET_MAX];
	__u32 shared_secret_len;
	char cram_hmac_alg[SHARED_SECRET_MAX];
	__u32 cram_hmac_alg_len;
	char integrity_alg[SHARED_SECRET_MAX];
	__u32 integrity_alg_len;
	char verify_alg[SHARED_SECRET_MAX];
	__u32 verify_alg_len;
	char csums_alg[SHARED_SECRET_MAX];
	__u32 csums_alg_len;
	__u32 wire_protocol;
	__u32 connect_int;
	__u32 timeout;
	__u32 ping_int;
	__u32 ping_timeo;
	__u32 sndbuf_size;
	__u32 rcvbuf_size;
	__u32 ko_count;
	__u32 max_epoch_size;
	__u32 after_sb_0p;
	__u32 after_sb_1p;
	__u32 after_sb_2p;
	__u32 rr_conflict;
	__u32 on_congestion;
	__u32 cong_fill;
	__u32 cong_extents;
	unsigned char two_primaries;
	unsigned char tcp_cork;
	unsigned char always_asbp;
	unsigned char use_rle;
	__u32 fencing_policy;
	char name[SHARED_SECRET_MAX];
	__u32 name_len;
	unsigned char csums_after_crash_only;
	__u32 sock_check_timeo;
	char transport_name[SHARED_SECRET_MAX];
	__u32 transport_name_len;
	__u32 max_buffers;
	unsigned char allow_remote_read;
	unsigned char tls;
	__s32 tls_privkey;
	__s32 tls_certificate;
	__s32 tls_keyring;
	unsigned char load_balance_paths;
	__u32 rdma_ctrl_rcvbuf_size;
	__u32 rdma_ctrl_sndbuf_size;
};

struct set_role_parms {
	unsigned char force;
};

struct resize_parms {
	__u64 resize_size;
	unsigned char resize_force;
	unsigned char no_resync;
	__u32 al_stripes;
	__u32 al_stripe_size;
};

struct start_ov_parms {
	__u64 ov_start_sector;
	__u64 ov_stop_sector;
};

struct new_c_uuid_parms {
	unsigned char clear_bm;
	unsigned char force_resync;
};

struct timeout_parms {
	__u32 timeout_type;
};

struct disconnect_parms {
	unsigned char force_disconnect;
};

struct detach_parms {
	unsigned char force_detach;
	unsigned char intentional_diskless_detach;
};

struct device_conf {
	__u32 max_bio_size;
	unsigned char intentional_diskless;
	__u32 block_size;
	__u32 discard_granularity;
};

struct resource_info {
	__u32 res_role;
	unsigned char res_susp;
	unsigned char res_susp_nod;
	unsigned char res_susp_fen;
	unsigned char res_susp_quorum;
	unsigned char res_fail_io;
};

struct device_info {
	__u32 dev_disk_state;
	unsigned char is_intentional_diskless;
	unsigned char dev_has_quorum;
	unsigned char dev_is_open;
	char backing_dev_path[128];
	__u32 backing_dev_path_len;
};

struct connection_info {
	__u32 conn_connection_state;
	__u32 conn_role;
};

struct peer_device_info {
	__u32 peer_repl_state;
	__u32 peer_disk_state;
	__u32 peer_resync_susp_user;
	__u32 peer_resync_susp_peer;
	__u32 peer_resync_susp_dependency;
	unsigned char peer_is_intentional_diskless;
	__u32 peer_resync_susp_max_parallel;
};

struct resource_statistics {
	__u32 res_stat_write_ordering;
};

struct device_statistics {
	__u64 dev_size;
	__u64 dev_read;
	__u64 dev_write;
	__u64 dev_al_writes;
	__u64 dev_bm_writes;
	__u32 dev_upper_pending;
	__u32 dev_lower_pending;
	unsigned char dev_upper_blocked;
	unsigned char dev_lower_blocked;
	unsigned char dev_al_suspended;
	__u64 dev_exposed_data_uuid;
	__u64 dev_current_uuid;
	__u32 dev_disk_flags;
	char history_uuids[HISTORY_UUIDS_SIZE];
	__u32 history_uuids_len;
};

struct connection_statistics {
	unsigned char conn_congested;
	__u64 ap_in_flight;
	__u64 rs_in_flight;
};

struct peer_device_statistics {
	__u64 peer_dev_received;
	__u64 peer_dev_sent;
	__u32 peer_dev_pending;
	__u32 peer_dev_unacked;
	__u64 peer_dev_out_of_sync;
	__u64 peer_dev_resync_failed;
	__u64 peer_dev_bitmap_uuid;
	__u32 peer_dev_flags;
	__u64 peer_dev_rs_total;
	__u64 peer_dev_ov_start_sector;
	__u64 peer_dev_ov_stop_sector;
	__u64 peer_dev_ov_position;
	__u64 peer_dev_ov_left;
	__u64 peer_dev_ov_skipped;
	__u64 peer_dev_rs_same_csum;
	__u64 peer_dev_rs_dt_start_ms;
	__u64 peer_dev_rs_paused_ms;
	__u64 peer_dev_rs_dt0_ms;
	__u64 peer_dev_rs_db0_sectors;
	__u64 peer_dev_rs_dt1_ms;
	__u64 peer_dev_rs_db1_sectors;
	__u32 peer_dev_rs_c_sync_rate;
	__u64 peer_dev_uuid_flags;
};

struct drbd_notification_header {
	__u32 nh_type;
};

struct drbd_helper_info {
	char helper_name[32];
	__u32 helper_name_len;
	__u32 helper_status;
};

struct invalidate_parms {
	__s32 sync_from_peer_node_id;
	unsigned char reset_bitmap;
};

struct forget_peer_parms {
	__s32 forget_peer_node_id;
};

struct peer_device_conf {
	__u32 resync_rate;
	__u32 c_plan_ahead;
	__u32 c_delay_target;
	__u32 c_fill_target;
	__u32 c_max_rate;
	__u32 c_min_rate;
	unsigned char bitmap;
	unsigned char resync_without_replication;
	unsigned char peer_tiebreaker;
};

struct path_parms {
	char my_addr[128];
	__u32 my_addr_len;
	char peer_addr[128];
	__u32 peer_addr_len;
};

struct connect_parms {
	unsigned char tentative;
	unsigned char discard_my_data;
};

struct drbd_path_info {
	unsigned char path_established;
};

struct rename_resource_parms {
	char new_resource_name[128];
	__u32 new_resource_name_len;
};

struct rename_resource_info {
	char res_new_name[128];
	__u32 res_new_name_len;
};

struct invalidate_peer_parms {
	unsigned char p_reset_bitmap;
};

struct suspend_io_parms {
	unsigned char bdev_freeze;
};

/* IS_SIGNED helpers for config_flags */
#define F_info_text_IS_SIGNED 0
#define F_ctx_peer_node_id_IS_SIGNED 0
#define F_ctx_volume_IS_SIGNED 0
#define F_ctx_resource_name_IS_SIGNED 0
#define F_ctx_my_addr_IS_SIGNED 0
#define F_ctx_peer_addr_IS_SIGNED 0
#define F_ctx_conn_name_IS_SIGNED 0
#define F_backing_dev_IS_SIGNED 0
#define F_meta_dev_IS_SIGNED 0
#define F_meta_dev_idx_IS_SIGNED 1
#define F_disk_size_IS_SIGNED 0
#define F_on_io_error_IS_SIGNED 0
#define F_resync_after_IS_SIGNED 1
#define F_al_extents_IS_SIGNED 0
#define F_disk_barrier_IS_SIGNED 0
#define F_disk_flushes_IS_SIGNED 0
#define F_disk_drain_IS_SIGNED 0
#define F_md_flushes_IS_SIGNED 0
#define F_disk_timeout_IS_SIGNED 0
#define F_read_balancing_IS_SIGNED 0
#define F_unplug_watermark_IS_SIGNED 0
#define F_rs_discard_granularity_IS_SIGNED 0
#define F_al_updates_IS_SIGNED 0
#define F_discard_zeroes_if_aligned_IS_SIGNED 0
#define F_disable_write_same_IS_SIGNED 0
#define F_d_bitmap_IS_SIGNED 0
#define F_cpu_mask_IS_SIGNED 0
#define F_on_no_data_IS_SIGNED 0
#define F_auto_promote_IS_SIGNED 0
#define F_node_id_IS_SIGNED 0
#define F_peer_ack_window_IS_SIGNED 0
#define F_twopc_timeout_IS_SIGNED 0
#define F_twopc_retry_timeout_IS_SIGNED 0
#define F_peer_ack_delay_IS_SIGNED 0
#define F_auto_promote_timeout_IS_SIGNED 0
#define F_nr_requests_IS_SIGNED 0
#define F_quorum_IS_SIGNED 1
#define F_on_no_quorum_IS_SIGNED 0
#define F_quorum_min_redundancy_IS_SIGNED 1
#define F_on_susp_primary_outdated_IS_SIGNED 0
#define F_drbd8_compat_mode_IS_SIGNED 0
#define F_explicit_drbd8_compat_IS_SIGNED 0
#define F_shared_secret_IS_SIGNED 0
#define F_cram_hmac_alg_IS_SIGNED 0
#define F_integrity_alg_IS_SIGNED 0
#define F_verify_alg_IS_SIGNED 0
#define F_csums_alg_IS_SIGNED 0
#define F_wire_protocol_IS_SIGNED 0
#define F_connect_int_IS_SIGNED 0
#define F_timeout_IS_SIGNED 0
#define F_ping_int_IS_SIGNED 0
#define F_ping_timeo_IS_SIGNED 0
#define F_sndbuf_size_IS_SIGNED 0
#define F_rcvbuf_size_IS_SIGNED 0
#define F_ko_count_IS_SIGNED 0
#define F_max_epoch_size_IS_SIGNED 0
#define F_after_sb_0p_IS_SIGNED 0
#define F_after_sb_1p_IS_SIGNED 0
#define F_after_sb_2p_IS_SIGNED 0
#define F_rr_conflict_IS_SIGNED 0
#define F_on_congestion_IS_SIGNED 0
#define F_cong_fill_IS_SIGNED 0
#define F_cong_extents_IS_SIGNED 0
#define F_two_primaries_IS_SIGNED 0
#define F_tcp_cork_IS_SIGNED 0
#define F_always_asbp_IS_SIGNED 0
#define F_use_rle_IS_SIGNED 0
#define F_fencing_policy_IS_SIGNED 0
#define F_name_IS_SIGNED 0
#define F_csums_after_crash_only_IS_SIGNED 0
#define F_sock_check_timeo_IS_SIGNED 0
#define F_transport_name_IS_SIGNED 0
#define F_max_buffers_IS_SIGNED 0
#define F_allow_remote_read_IS_SIGNED 0
#define F_tls_IS_SIGNED 0
#define F_tls_privkey_IS_SIGNED 1
#define F_tls_certificate_IS_SIGNED 1
#define F_tls_keyring_IS_SIGNED 1
#define F_load_balance_paths_IS_SIGNED 0
#define F_rdma_ctrl_rcvbuf_size_IS_SIGNED 0
#define F_rdma_ctrl_sndbuf_size_IS_SIGNED 0
#define F_force_IS_SIGNED 0
#define F_resize_size_IS_SIGNED 0
#define F_resize_force_IS_SIGNED 0
#define F_no_resync_IS_SIGNED 0
#define F_al_stripes_IS_SIGNED 0
#define F_al_stripe_size_IS_SIGNED 0
#define F_ov_start_sector_IS_SIGNED 0
#define F_ov_stop_sector_IS_SIGNED 0
#define F_clear_bm_IS_SIGNED 0
#define F_force_resync_IS_SIGNED 0
#define F_timeout_type_IS_SIGNED 0
#define F_force_disconnect_IS_SIGNED 0
#define F_force_detach_IS_SIGNED 0
#define F_intentional_diskless_detach_IS_SIGNED 0
#define F_max_bio_size_IS_SIGNED 0
#define F_intentional_diskless_IS_SIGNED 0
#define F_block_size_IS_SIGNED 0
#define F_discard_granularity_IS_SIGNED 0
#define F_res_role_IS_SIGNED 0
#define F_res_susp_IS_SIGNED 0
#define F_res_susp_nod_IS_SIGNED 0
#define F_res_susp_fen_IS_SIGNED 0
#define F_res_susp_quorum_IS_SIGNED 0
#define F_res_fail_io_IS_SIGNED 0
#define F_dev_disk_state_IS_SIGNED 0
#define F_is_intentional_diskless_IS_SIGNED 0
#define F_dev_has_quorum_IS_SIGNED 0
#define F_dev_is_open_IS_SIGNED 0
#define F_backing_dev_path_IS_SIGNED 0
#define F_conn_connection_state_IS_SIGNED 0
#define F_conn_role_IS_SIGNED 0
#define F_peer_repl_state_IS_SIGNED 0
#define F_peer_disk_state_IS_SIGNED 0
#define F_peer_resync_susp_user_IS_SIGNED 0
#define F_peer_resync_susp_peer_IS_SIGNED 0
#define F_peer_resync_susp_dependency_IS_SIGNED 0
#define F_peer_is_intentional_diskless_IS_SIGNED 0
#define F_peer_resync_susp_max_parallel_IS_SIGNED 0
#define F_res_stat_write_ordering_IS_SIGNED 0
#define F_dev_size_IS_SIGNED 0
#define F_dev_read_IS_SIGNED 0
#define F_dev_write_IS_SIGNED 0
#define F_dev_al_writes_IS_SIGNED 0
#define F_dev_bm_writes_IS_SIGNED 0
#define F_dev_upper_pending_IS_SIGNED 0
#define F_dev_lower_pending_IS_SIGNED 0
#define F_dev_upper_blocked_IS_SIGNED 0
#define F_dev_lower_blocked_IS_SIGNED 0
#define F_dev_al_suspended_IS_SIGNED 0
#define F_dev_exposed_data_uuid_IS_SIGNED 0
#define F_dev_current_uuid_IS_SIGNED 0
#define F_dev_disk_flags_IS_SIGNED 0
#define F_history_uuids_IS_SIGNED 0
#define F_conn_congested_IS_SIGNED 0
#define F_ap_in_flight_IS_SIGNED 0
#define F_rs_in_flight_IS_SIGNED 0
#define F_peer_dev_received_IS_SIGNED 0
#define F_peer_dev_sent_IS_SIGNED 0
#define F_peer_dev_pending_IS_SIGNED 0
#define F_peer_dev_unacked_IS_SIGNED 0
#define F_peer_dev_out_of_sync_IS_SIGNED 0
#define F_peer_dev_resync_failed_IS_SIGNED 0
#define F_peer_dev_bitmap_uuid_IS_SIGNED 0
#define F_peer_dev_flags_IS_SIGNED 0
#define F_peer_dev_rs_total_IS_SIGNED 0
#define F_peer_dev_ov_start_sector_IS_SIGNED 0
#define F_peer_dev_ov_stop_sector_IS_SIGNED 0
#define F_peer_dev_ov_position_IS_SIGNED 0
#define F_peer_dev_ov_left_IS_SIGNED 0
#define F_peer_dev_ov_skipped_IS_SIGNED 0
#define F_peer_dev_rs_same_csum_IS_SIGNED 0
#define F_peer_dev_rs_dt_start_ms_IS_SIGNED 0
#define F_peer_dev_rs_paused_ms_IS_SIGNED 0
#define F_peer_dev_rs_dt0_ms_IS_SIGNED 0
#define F_peer_dev_rs_db0_sectors_IS_SIGNED 0
#define F_peer_dev_rs_dt1_ms_IS_SIGNED 0
#define F_peer_dev_rs_db1_sectors_IS_SIGNED 0
#define F_peer_dev_rs_c_sync_rate_IS_SIGNED 0
#define F_peer_dev_uuid_flags_IS_SIGNED 0
#define F_nh_type_IS_SIGNED 0
#define F_helper_name_IS_SIGNED 0
#define F_helper_status_IS_SIGNED 0
#define F_sync_from_peer_node_id_IS_SIGNED 1
#define F_reset_bitmap_IS_SIGNED 0
#define F_forget_peer_node_id_IS_SIGNED 1
#define F_resync_rate_IS_SIGNED 0
#define F_c_plan_ahead_IS_SIGNED 0
#define F_c_delay_target_IS_SIGNED 0
#define F_c_fill_target_IS_SIGNED 0
#define F_c_max_rate_IS_SIGNED 0
#define F_c_min_rate_IS_SIGNED 0
#define F_bitmap_IS_SIGNED 0
#define F_resync_without_replication_IS_SIGNED 0
#define F_peer_tiebreaker_IS_SIGNED 0
#define F_my_addr_IS_SIGNED 0
#define F_peer_addr_IS_SIGNED 0
#define F_tentative_IS_SIGNED 0
#define F_discard_my_data_IS_SIGNED 0
#define F_path_established_IS_SIGNED 0
#define F_new_resource_name_IS_SIGNED 0
#define F_res_new_name_IS_SIGNED 0
#define F_p_reset_bitmap_IS_SIGNED 0
#define F_bdev_freeze_IS_SIGNED 0

int drbd_cfg_reply_from_attrs(struct drbd_cfg_reply *s, struct genl_info *info);
int drbd_cfg_reply_ntb_from_attrs(struct nlattr ***ret_nested_attribute_table, struct genl_info *info);

int drbd_cfg_context_from_attrs(struct drbd_cfg_context *s, struct genl_info *info);
int drbd_cfg_context_ntb_from_attrs(struct nlattr ***ret_nested_attribute_table, struct genl_info *info);
void set_drbd_cfg_context_defaults(struct drbd_cfg_context *x);

int disk_conf_from_attrs(struct disk_conf *s, struct genl_info *info);
int disk_conf_ntb_from_attrs(struct nlattr ***ret_nested_attribute_table, struct genl_info *info);
void set_disk_conf_defaults(struct disk_conf *x);

int res_opts_from_attrs(struct res_opts *s, struct genl_info *info);
int res_opts_ntb_from_attrs(struct nlattr ***ret_nested_attribute_table, struct genl_info *info);
void set_res_opts_defaults(struct res_opts *x);

int net_conf_from_attrs(struct net_conf *s, struct genl_info *info);
int net_conf_ntb_from_attrs(struct nlattr ***ret_nested_attribute_table, struct genl_info *info);
void set_net_conf_defaults(struct net_conf *x);

int set_role_parms_from_attrs(struct set_role_parms *s, struct genl_info *info);
int set_role_parms_ntb_from_attrs(struct nlattr ***ret_nested_attribute_table, struct genl_info *info);

int resize_parms_from_attrs(struct resize_parms *s, struct genl_info *info);
int resize_parms_ntb_from_attrs(struct nlattr ***ret_nested_attribute_table, struct genl_info *info);
void set_resize_parms_defaults(struct resize_parms *x);

int start_ov_parms_from_attrs(struct start_ov_parms *s, struct genl_info *info);
int start_ov_parms_ntb_from_attrs(struct nlattr ***ret_nested_attribute_table, struct genl_info *info);

int new_c_uuid_parms_from_attrs(struct new_c_uuid_parms *s, struct genl_info *info);
int new_c_uuid_parms_ntb_from_attrs(struct nlattr ***ret_nested_attribute_table, struct genl_info *info);

int timeout_parms_from_attrs(struct timeout_parms *s, struct genl_info *info);
int timeout_parms_ntb_from_attrs(struct nlattr ***ret_nested_attribute_table, struct genl_info *info);

int disconnect_parms_from_attrs(struct disconnect_parms *s, struct genl_info *info);
int disconnect_parms_ntb_from_attrs(struct nlattr ***ret_nested_attribute_table, struct genl_info *info);

int detach_parms_from_attrs(struct detach_parms *s, struct genl_info *info);
int detach_parms_ntb_from_attrs(struct nlattr ***ret_nested_attribute_table, struct genl_info *info);
void set_detach_parms_defaults(struct detach_parms *x);

int device_conf_from_attrs(struct device_conf *s, struct genl_info *info);
int device_conf_ntb_from_attrs(struct nlattr ***ret_nested_attribute_table, struct genl_info *info);
void set_device_conf_defaults(struct device_conf *x);

int resource_info_from_attrs(struct resource_info *s, struct genl_info *info);
int resource_info_ntb_from_attrs(struct nlattr ***ret_nested_attribute_table, struct genl_info *info);

int device_info_from_attrs(struct device_info *s, struct genl_info *info);
int device_info_ntb_from_attrs(struct nlattr ***ret_nested_attribute_table, struct genl_info *info);

int connection_info_from_attrs(struct connection_info *s, struct genl_info *info);
int connection_info_ntb_from_attrs(struct nlattr ***ret_nested_attribute_table, struct genl_info *info);

int peer_device_info_from_attrs(struct peer_device_info *s, struct genl_info *info);
int peer_device_info_ntb_from_attrs(struct nlattr ***ret_nested_attribute_table, struct genl_info *info);

int resource_statistics_from_attrs(struct resource_statistics *s, struct genl_info *info);
int resource_statistics_ntb_from_attrs(struct nlattr ***ret_nested_attribute_table, struct genl_info *info);

int device_statistics_from_attrs(struct device_statistics *s, struct genl_info *info);
int device_statistics_ntb_from_attrs(struct nlattr ***ret_nested_attribute_table, struct genl_info *info);

int connection_statistics_from_attrs(struct connection_statistics *s, struct genl_info *info);
int connection_statistics_ntb_from_attrs(struct nlattr ***ret_nested_attribute_table, struct genl_info *info);

int peer_device_statistics_from_attrs(struct peer_device_statistics *s, struct genl_info *info);
int peer_device_statistics_ntb_from_attrs(struct nlattr ***ret_nested_attribute_table, struct genl_info *info);

int drbd_notification_header_from_attrs(struct drbd_notification_header *s, struct genl_info *info);
int drbd_notification_header_ntb_from_attrs(struct nlattr ***ret_nested_attribute_table, struct genl_info *info);

int drbd_helper_info_from_attrs(struct drbd_helper_info *s, struct genl_info *info);
int drbd_helper_info_ntb_from_attrs(struct nlattr ***ret_nested_attribute_table, struct genl_info *info);

int invalidate_parms_from_attrs(struct invalidate_parms *s, struct genl_info *info);
int invalidate_parms_ntb_from_attrs(struct nlattr ***ret_nested_attribute_table, struct genl_info *info);
void set_invalidate_parms_defaults(struct invalidate_parms *x);

int forget_peer_parms_from_attrs(struct forget_peer_parms *s, struct genl_info *info);
int forget_peer_parms_ntb_from_attrs(struct nlattr ***ret_nested_attribute_table, struct genl_info *info);
void set_forget_peer_parms_defaults(struct forget_peer_parms *x);

int peer_device_conf_from_attrs(struct peer_device_conf *s, struct genl_info *info);
int peer_device_conf_ntb_from_attrs(struct nlattr ***ret_nested_attribute_table, struct genl_info *info);
void set_peer_device_conf_defaults(struct peer_device_conf *x);

int path_parms_from_attrs(struct path_parms *s, struct genl_info *info);
int path_parms_ntb_from_attrs(struct nlattr ***ret_nested_attribute_table, struct genl_info *info);

int connect_parms_from_attrs(struct connect_parms *s, struct genl_info *info);
int connect_parms_ntb_from_attrs(struct nlattr ***ret_nested_attribute_table, struct genl_info *info);
void set_connect_parms_defaults(struct connect_parms *x);

int drbd_path_info_from_attrs(struct drbd_path_info *s, struct genl_info *info);
int drbd_path_info_ntb_from_attrs(struct nlattr ***ret_nested_attribute_table, struct genl_info *info);

int rename_resource_parms_from_attrs(struct rename_resource_parms *s, struct genl_info *info);
int rename_resource_parms_ntb_from_attrs(struct nlattr ***ret_nested_attribute_table, struct genl_info *info);

int rename_resource_info_from_attrs(struct rename_resource_info *s, struct genl_info *info);
int rename_resource_info_ntb_from_attrs(struct nlattr ***ret_nested_attribute_table, struct genl_info *info);

int invalidate_peer_parms_from_attrs(struct invalidate_peer_parms *s, struct genl_info *info);
int invalidate_peer_parms_ntb_from_attrs(struct nlattr ***ret_nested_attribute_table, struct genl_info *info);
void set_invalidate_peer_parms_defaults(struct invalidate_peer_parms *x);

int suspend_io_parms_from_attrs(struct suspend_io_parms *s, struct genl_info *info);
int suspend_io_parms_ntb_from_attrs(struct nlattr ***ret_nested_attribute_table, struct genl_info *info);
void set_suspend_io_parms_defaults(struct suspend_io_parms *x);

#define DRBD_TLA_NL_POLICY_LEN (DRBD_NLA_SUSPEND_IO_PARAMS + 1)
extern const struct nla_policy drbd_tla_nl_policy[DRBD_TLA_NL_POLICY_LEN];

#endif /* _LINUX_DRBD_GEN_USERSPACE_H */
