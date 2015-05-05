#ifndef __RDPDK_CMDLINE_H
#define __RDPDK_CMDLINE_H

int rdpdk_cmdline_init(const char *path);
int rdpdk_cmdline_launch(int sock);
int rdpdk_cmdline_stop(int sock, const char *path);

#endif
