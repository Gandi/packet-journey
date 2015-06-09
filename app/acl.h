#ifndef __RDPDK_ACL_H
#define __RDPDK_ACL_H

#define OPTION_RULE_IPV4	"rule_ipv4"
#define OPTION_RULE_IPV6	"rule_ipv6"
#define OPTION_SCALAR		"scalar"

int acl_init(int numa_on);

struct acl_config {
	const char *rule_ipv4_name;
	const char *rule_ipv6_name;
	int scalar;
};

extern struct acl_config acl_parm_config;


#endif
