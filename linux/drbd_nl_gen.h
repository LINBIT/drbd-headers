/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-3-Clause) */
/* Do not edit directly, auto-generated from: */
/*	drbd_genl_ynl.yaml */
/* YNL-GEN kernel header */
/* To regenerate run: tools/net/ynl/ynl-regen.sh */

#ifndef _LINUX_DRBD_GEN_H
#define _LINUX_DRBD_GEN_H

#include <net/netlink.h>
#include <net/genetlink.h>

#include <uapi/linux/drbd_genl.h>
#include <linux/drbd.h>
#include <linux/drbd_limits.h>

/* Common nested types */
extern const struct nla_policy drbd_connect_parms_nl_policy[DRBD_A_CONNECT_PARMS_DISCARD_MY_DATA + 1];
extern const struct nla_policy drbd_detach_parms_nl_policy[DRBD_A_DETACH_PARMS_INTENTIONAL_DISKLESS_DETACH + 1];
extern const struct nla_policy drbd_device_conf_nl_policy[DRBD_A_DEVICE_CONF_DISCARD_GRANULARITY + 1];
extern const struct nla_policy drbd_disconnect_parms_nl_policy[DRBD_A_DISCONNECT_PARMS_FORCE_DISCONNECT + 1];
extern const struct nla_policy drbd_disk_conf_nl_policy[DRBD_A_DISK_CONF_D_BITMAP + 1];
extern const struct nla_policy drbd_drbd_cfg_context_nl_policy[DRBD_A_DRBD_CFG_CONTEXT_CTX_PEER_NODE_ID + 1];
extern const struct nla_policy drbd_forget_peer_parms_nl_policy[DRBD_A_FORGET_PEER_PARMS_FORGET_PEER_NODE_ID + 1];
extern const struct nla_policy drbd_invalidate_parms_nl_policy[DRBD_A_INVALIDATE_PARMS_RESET_BITMAP + 1];
extern const struct nla_policy drbd_invalidate_peer_parms_nl_policy[DRBD_A_INVALIDATE_PEER_PARMS_P_RESET_BITMAP + 1];
extern const struct nla_policy drbd_net_conf_nl_policy[DRBD_A_NET_CONF_RDMA_CTRL_SNDBUF_SIZE + 1];
extern const struct nla_policy drbd_new_c_uuid_parms_nl_policy[DRBD_A_NEW_C_UUID_PARMS_FORCE_RESYNC + 1];
extern const struct nla_policy drbd_path_parms_nl_policy[DRBD_A_PATH_PARMS_PEER_ADDR + 1];
extern const struct nla_policy drbd_peer_device_conf_nl_policy[DRBD_A_PEER_DEVICE_CONF_PEER_TIEBREAKER + 1];
extern const struct nla_policy drbd_rename_resource_parms_nl_policy[DRBD_A_RENAME_RESOURCE_PARMS_NEW_RESOURCE_NAME + 1];
extern const struct nla_policy drbd_res_opts_nl_policy[DRBD_A_RES_OPTS_EXPLICIT_DRBD8_COMPAT + 1];
extern const struct nla_policy drbd_resize_parms_nl_policy[DRBD_A_RESIZE_PARMS_AL_STRIPE_SIZE + 1];
extern const struct nla_policy drbd_set_role_parms_nl_policy[DRBD_A_SET_ROLE_PARMS_FORCE + 1];
extern const struct nla_policy drbd_start_ov_parms_nl_policy[DRBD_A_START_OV_PARMS_OV_STOP_SECTOR + 1];
extern const struct nla_policy drbd_suspend_io_parms_nl_policy[DRBD_A_SUSPEND_IO_PARMS_BDEV_FREEZE + 1];

/* Ops table for drbd */
extern const struct genl_split_ops drbd_nl_ops[38];

int drbd_pre_doit(const struct genl_split_ops *ops, struct sk_buff *skb,
		  struct genl_info *info);
void
drbd_post_doit(const struct genl_split_ops *ops, struct sk_buff *skb,
	       struct genl_info *info);
int drbd_nl_get_devices_done(struct netlink_callback *cb);
int drbd_nl_get_connections_done(struct netlink_callback *cb);
int drbd_nl_get_peer_devices_done(struct netlink_callback *cb);
int drbd_nl_get_initial_state_done(struct netlink_callback *cb);
int drbd_nl_get_paths_done(struct netlink_callback *cb);

int drbd_nl_new_minor_doit(struct sk_buff *skb, struct genl_info *info);
int drbd_nl_del_minor_doit(struct sk_buff *skb, struct genl_info *info);
int drbd_nl_new_resource_doit(struct sk_buff *skb, struct genl_info *info);
int drbd_nl_del_resource_doit(struct sk_buff *skb, struct genl_info *info);
int drbd_nl_resource_opts_doit(struct sk_buff *skb, struct genl_info *info);
int drbd_nl_connect_doit(struct sk_buff *skb, struct genl_info *info);
int drbd_nl_disconnect_doit(struct sk_buff *skb, struct genl_info *info);
int drbd_nl_attach_doit(struct sk_buff *skb, struct genl_info *info);
int drbd_nl_resize_doit(struct sk_buff *skb, struct genl_info *info);
int drbd_nl_primary_doit(struct sk_buff *skb, struct genl_info *info);
int drbd_nl_secondary_doit(struct sk_buff *skb, struct genl_info *info);
int drbd_nl_new_c_uuid_doit(struct sk_buff *skb, struct genl_info *info);
int drbd_nl_start_ov_doit(struct sk_buff *skb, struct genl_info *info);
int drbd_nl_detach_doit(struct sk_buff *skb, struct genl_info *info);
int drbd_nl_invalidate_doit(struct sk_buff *skb, struct genl_info *info);
int drbd_nl_invalidate_peer_doit(struct sk_buff *skb, struct genl_info *info);
int drbd_nl_pause_sync_doit(struct sk_buff *skb, struct genl_info *info);
int drbd_nl_resume_sync_doit(struct sk_buff *skb, struct genl_info *info);
int drbd_nl_suspend_io_doit(struct sk_buff *skb, struct genl_info *info);
int drbd_nl_resume_io_doit(struct sk_buff *skb, struct genl_info *info);
int drbd_nl_outdate_doit(struct sk_buff *skb, struct genl_info *info);
int drbd_nl_get_timeout_type_doit(struct sk_buff *skb, struct genl_info *info);
int drbd_nl_down_doit(struct sk_buff *skb, struct genl_info *info);
int drbd_nl_disk_opts_doit(struct sk_buff *skb, struct genl_info *info);
int drbd_nl_net_opts_doit(struct sk_buff *skb, struct genl_info *info);
int drbd_nl_get_resources_dumpit(struct sk_buff *skb,
				 struct netlink_callback *cb);
int drbd_nl_get_devices_dumpit(struct sk_buff *skb,
			       struct netlink_callback *cb);
int drbd_nl_get_connections_dumpit(struct sk_buff *skb,
				   struct netlink_callback *cb);
int drbd_nl_get_peer_devices_dumpit(struct sk_buff *skb,
				    struct netlink_callback *cb);
int drbd_nl_get_initial_state_dumpit(struct sk_buff *skb,
				     struct netlink_callback *cb);
int drbd_nl_forget_peer_doit(struct sk_buff *skb, struct genl_info *info);
int drbd_nl_peer_device_opts_doit(struct sk_buff *skb, struct genl_info *info);
int drbd_nl_new_peer_doit(struct sk_buff *skb, struct genl_info *info);
int drbd_nl_new_path_doit(struct sk_buff *skb, struct genl_info *info);
int drbd_nl_del_peer_doit(struct sk_buff *skb, struct genl_info *info);
int drbd_nl_del_path_doit(struct sk_buff *skb, struct genl_info *info);
int drbd_nl_rename_resource_doit(struct sk_buff *skb, struct genl_info *info);
int drbd_nl_get_paths_dumpit(struct sk_buff *skb, struct netlink_callback *cb);

enum {
	DRBD_NLGRP_EVENTS,
};

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

int drbd_cfg_reply_to_skb(struct sk_buff *skb, struct drbd_cfg_reply *s);

int drbd_cfg_context_from_attrs(struct drbd_cfg_context *s, struct genl_info *info);
int drbd_cfg_context_ntb_from_attrs(struct nlattr ***ret_nested_attribute_table, struct genl_info *info);
int drbd_cfg_context_to_skb(struct sk_buff *skb, struct drbd_cfg_context *s);
void set_drbd_cfg_context_defaults(struct drbd_cfg_context *x);

int disk_conf_from_attrs(struct disk_conf *s, struct genl_info *info);
int disk_conf_ntb_from_attrs(struct nlattr ***ret_nested_attribute_table, struct genl_info *info);
int disk_conf_to_skb(struct sk_buff *skb, struct disk_conf *s);
void set_disk_conf_defaults(struct disk_conf *x);

int res_opts_from_attrs(struct res_opts *s, struct genl_info *info);
int res_opts_ntb_from_attrs(struct nlattr ***ret_nested_attribute_table, struct genl_info *info);
int res_opts_to_skb(struct sk_buff *skb, struct res_opts *s);
void set_res_opts_defaults(struct res_opts *x);

int net_conf_from_attrs(struct net_conf *s, struct genl_info *info);
int net_conf_ntb_from_attrs(struct nlattr ***ret_nested_attribute_table, struct genl_info *info);
int net_conf_to_skb(struct sk_buff *skb, struct net_conf *s);
void set_net_conf_defaults(struct net_conf *x);

int set_role_parms_from_attrs(struct set_role_parms *s, struct genl_info *info);
int set_role_parms_ntb_from_attrs(struct nlattr ***ret_nested_attribute_table, struct genl_info *info);
int set_role_parms_to_skb(struct sk_buff *skb, struct set_role_parms *s);

int resize_parms_from_attrs(struct resize_parms *s, struct genl_info *info);
int resize_parms_ntb_from_attrs(struct nlattr ***ret_nested_attribute_table, struct genl_info *info);
int resize_parms_to_skb(struct sk_buff *skb, struct resize_parms *s);
void set_resize_parms_defaults(struct resize_parms *x);

int start_ov_parms_from_attrs(struct start_ov_parms *s, struct genl_info *info);
int start_ov_parms_ntb_from_attrs(struct nlattr ***ret_nested_attribute_table, struct genl_info *info);
int start_ov_parms_to_skb(struct sk_buff *skb, struct start_ov_parms *s);

int new_c_uuid_parms_from_attrs(struct new_c_uuid_parms *s, struct genl_info *info);
int new_c_uuid_parms_ntb_from_attrs(struct nlattr ***ret_nested_attribute_table, struct genl_info *info);
int new_c_uuid_parms_to_skb(struct sk_buff *skb, struct new_c_uuid_parms *s);

int timeout_parms_to_skb(struct sk_buff *skb, struct timeout_parms *s);

int disconnect_parms_from_attrs(struct disconnect_parms *s, struct genl_info *info);
int disconnect_parms_ntb_from_attrs(struct nlattr ***ret_nested_attribute_table, struct genl_info *info);
int disconnect_parms_to_skb(struct sk_buff *skb, struct disconnect_parms *s);

int detach_parms_from_attrs(struct detach_parms *s, struct genl_info *info);
int detach_parms_ntb_from_attrs(struct nlattr ***ret_nested_attribute_table, struct genl_info *info);
int detach_parms_to_skb(struct sk_buff *skb, struct detach_parms *s);
void set_detach_parms_defaults(struct detach_parms *x);

int device_conf_from_attrs(struct device_conf *s, struct genl_info *info);
int device_conf_ntb_from_attrs(struct nlattr ***ret_nested_attribute_table, struct genl_info *info);
int device_conf_to_skb(struct sk_buff *skb, struct device_conf *s);
void set_device_conf_defaults(struct device_conf *x);

int resource_info_to_skb(struct sk_buff *skb, struct resource_info *s);

int device_info_to_skb(struct sk_buff *skb, struct device_info *s);

int connection_info_to_skb(struct sk_buff *skb, struct connection_info *s);

int peer_device_info_to_skb(struct sk_buff *skb, struct peer_device_info *s);

int resource_statistics_to_skb(struct sk_buff *skb, struct resource_statistics *s);

int device_statistics_to_skb(struct sk_buff *skb, struct device_statistics *s);

int connection_statistics_to_skb(struct sk_buff *skb, struct connection_statistics *s);

int peer_device_statistics_to_skb(struct sk_buff *skb, struct peer_device_statistics *s);

int drbd_notification_header_to_skb(struct sk_buff *skb, struct drbd_notification_header *s);

int drbd_helper_info_to_skb(struct sk_buff *skb, struct drbd_helper_info *s);

int invalidate_parms_from_attrs(struct invalidate_parms *s, struct genl_info *info);
int invalidate_parms_ntb_from_attrs(struct nlattr ***ret_nested_attribute_table, struct genl_info *info);
int invalidate_parms_to_skb(struct sk_buff *skb, struct invalidate_parms *s);
void set_invalidate_parms_defaults(struct invalidate_parms *x);

int forget_peer_parms_from_attrs(struct forget_peer_parms *s, struct genl_info *info);
int forget_peer_parms_ntb_from_attrs(struct nlattr ***ret_nested_attribute_table, struct genl_info *info);
int forget_peer_parms_to_skb(struct sk_buff *skb, struct forget_peer_parms *s);
void set_forget_peer_parms_defaults(struct forget_peer_parms *x);

int peer_device_conf_from_attrs(struct peer_device_conf *s, struct genl_info *info);
int peer_device_conf_ntb_from_attrs(struct nlattr ***ret_nested_attribute_table, struct genl_info *info);
int peer_device_conf_to_skb(struct sk_buff *skb, struct peer_device_conf *s);
void set_peer_device_conf_defaults(struct peer_device_conf *x);

int path_parms_from_attrs(struct path_parms *s, struct genl_info *info);
int path_parms_ntb_from_attrs(struct nlattr ***ret_nested_attribute_table, struct genl_info *info);
int path_parms_to_skb(struct sk_buff *skb, struct path_parms *s);

int connect_parms_from_attrs(struct connect_parms *s, struct genl_info *info);
int connect_parms_ntb_from_attrs(struct nlattr ***ret_nested_attribute_table, struct genl_info *info);
int connect_parms_to_skb(struct sk_buff *skb, struct connect_parms *s);
void set_connect_parms_defaults(struct connect_parms *x);

int drbd_path_info_to_skb(struct sk_buff *skb, struct drbd_path_info *s);

int rename_resource_parms_from_attrs(struct rename_resource_parms *s, struct genl_info *info);
int rename_resource_parms_ntb_from_attrs(struct nlattr ***ret_nested_attribute_table, struct genl_info *info);
int rename_resource_parms_to_skb(struct sk_buff *skb, struct rename_resource_parms *s);

int rename_resource_info_to_skb(struct sk_buff *skb, struct rename_resource_info *s);

int invalidate_peer_parms_from_attrs(struct invalidate_peer_parms *s, struct genl_info *info);
int invalidate_peer_parms_ntb_from_attrs(struct nlattr ***ret_nested_attribute_table, struct genl_info *info);
int invalidate_peer_parms_to_skb(struct sk_buff *skb, struct invalidate_peer_parms *s);
void set_invalidate_peer_parms_defaults(struct invalidate_peer_parms *x);

int suspend_io_parms_from_attrs(struct suspend_io_parms *s, struct genl_info *info);
int suspend_io_parms_ntb_from_attrs(struct nlattr ***ret_nested_attribute_table, struct genl_info *info);
int suspend_io_parms_to_skb(struct sk_buff *skb, struct suspend_io_parms *s);
void set_suspend_io_parms_defaults(struct suspend_io_parms *x);

#endif /* _LINUX_DRBD_GEN_H */
