/****************************************************************************
 *  Traffic Analyzer : Handle Socket  (definitions)
 ***************************************************************************/

#ifndef INCLUDE_NETSOCK_H
#define INCLUDE_NETSOCK_H

#define UNUSED(x) (void)x

int open_netreceive_socket (const char *pSocketName);
int write_netreceive_socket (int fd_socket, char* pTextStat);

#endif
