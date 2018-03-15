/******************************************************************************
 *
 * Copyright (c) 2018, Kontron Europe GmbH
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 *****************************************************************************/

/******************************************************************************
 * Traffic Analyzer: Handle Socket
 *-----------------------------------------------------------------------------
 *
 * Description:
 *   Open a UNIX domain socket and write measured result on socket.
 *   This is an option for the Traffic Analyzer.
 *
 *****************************************************************************/

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
