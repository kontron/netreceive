/****************************************************************************
 *  Traffic Analyzer: Handle Socket
 *---------------------------------------------------------------------------
 *  Open a UNIX domain socket and write result on socket.
 *  This is an option for the Traffic Analyzer.
 *
 *  ## Copyright ## T.B.D.
 *
 ***************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "netsock.h"

/*--------------------------------------------------------------------------
 *  Domain Socket
 *------------------------------------------------------------------------*/

int open_netreceive_socket (const char *pSocketName)
{
    struct sockaddr_un addr;
    int sock;

    umask(0);

    if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        perror("socket error");
        exit(-1);
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, pSocketName, sizeof(addr.sun_path)-1);
    unlink(pSocketName);

    if (bind (sock, (struct sockaddr*) &addr, sizeof(addr)) == -1) {
        perror("bind error");
        exit(-1);
    }

    if (listen(sock, 5) == -1) {
        perror("listen error");
        exit(-1);
    }

    return sock;
}

/*----- run server socket ------------------------------------------------*/

#define MAX_CLIENTS 2
static int client_socket[MAX_CLIENTS];
static int max_fd;

int write_netreceive_socket (int fd_socket, char* pTextStat)
{
    int i;
    int sd;
    int activity;
    int new_socket;
    fd_set readfds;

    FD_ZERO(&readfds);
    FD_SET(fd_socket, &readfds);
    max_fd = fd_socket;

    /* add child sockets to set */
    for (i = 0 ; i < MAX_CLIENTS; i++) {
        sd = client_socket[i];
        if (sd > 0) {
            FD_SET(sd, &readfds);
        }

        if (sd > max_fd) {
            max_fd = sd;
        }
    }

    struct timeval waitd = {0, 0};
    activity = select(max_fd + 1, &readfds, NULL, NULL, &waitd);
    if ((activity < 0) && (errno != EINTR)) {
        perror("select error");
    }

    /* check for new incoming connection */
    if (FD_ISSET(fd_socket, &readfds)) {
        if ((new_socket = accept(fd_socket, NULL, NULL)) < 0) {
            perror("accept");
            return 0;
        }


        /* todo check for max reached ... */
        for (i = 0 ; i < MAX_CLIENTS; i++) {
            if (client_socket[i] == 0) {
                client_socket[i] = new_socket;
                break;
            }
        }
    }

    /* handle all active connecitons */
    for (i = 0; i < MAX_CLIENTS; i++) {
        sd = client_socket[i];
        if (sd == 0) {
            continue;
        }
        if (FD_ISSET(sd, &readfds)) {
            char t[32];
            if (read(sd, t, 32) == 0) {
                close(sd);
                client_socket[i] = 0;
            }
        }

        if (write(sd, pTextStat, strlen(pTextStat)) <= 0) {
            client_socket[i] = 0;
        }
    }

    return 0;
}

/*--- end-of-file ---*/
