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
extern const struct genl_ops drbd_nl_ops[38];

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

#include <linux/drbd_nl_types.h>

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
