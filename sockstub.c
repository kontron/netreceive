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

/*****************************************************************************
 * Client-Socket Stub (for testing only)
 *----------------------------------------------------------------------------
 *
 * Description:
 *   Connects to a UNIX domain socket and prints the received messages.
 *
 * Note:
 *    Simple implementation, argument is the socket name, no options exists.
 *
 ****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#define USAGE "sockstub <socket-name>"

static void handle_socket (char* socketName)
{
    struct sockaddr_un client;
    int  sock;
    char buf[128];
    int  rc;

    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
        perror ("socket");
        exit (1);
    }
    client.sun_family = AF_UNIX;
    strcpy(client.sun_path, socketName);

    if (connect(sock, (struct sockaddr *) &client, sizeof(struct sockaddr_un))
                                                                        < 0) {
        perror ("connect");
        close (sock);
        exit (1);
    }

    while (1) {
        memset(buf, 0, sizeof(buf));
        if ((rc = read(sock, buf, sizeof(buf))) < 0) {
            perror("reading stream message");
        } else if (rc > 0) {
            printf("MSG: %s\n", buf);
        }
    }
    close(sock);
}

int main(int argc, char** argv)
{
    if (argc != 2) {
        fprintf(stderr, "%s\n", USAGE);
        return (-1);
    }

    handle_socket(argv[1]);

    exit (0);
}
