/*****************************************************************************
 *  Client-Socket Stub (for testing)
 *----------------------------------------------------------------------------
 *  Connects to a UNIX domain socket and prints the received messages.
 *
 *  Note: Simple implementation, argument is the socket name, no options
 *        exist.
 *
 *  ## Copyright ## T.B.D.
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
