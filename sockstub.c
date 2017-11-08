/*****************************************************************************
 * Client-Socket Stub
 *
 * Simple implementation, sets static values for the response messages.
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

#define NAME "/tmp/motor_cmd_msg.socket"

#define UNUSED(x) (void)(x)

int main(int argc, char** argv)
{
    int sock;
    struct sockaddr_un client;
    char buf[128];
    int rc;

    UNUSED(argc);
    UNUSED(argv);

    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        return (-1);
    }
    client.sun_family = AF_UNIX;
    strcpy(client.sun_path, "/tmp/traffic.socket");

    if (connect(sock, (struct sockaddr *) &client, sizeof(struct sockaddr_un)) < 0) {
        perror("connect");
        close(sock);
        exit(1);
    }

    while (1) {
        if ((rc = read(sock, buf, sizeof(buf))) < 0)
            perror("reading stream message");
        else if (rc > 0) {
            printf("MSG: %s\n", buf);
        }
    }
    close(sock);

    exit(0);
}
