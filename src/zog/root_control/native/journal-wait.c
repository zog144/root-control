/* Copyright (c) 2026 Alex Black.
 * SPDX-License-Identifier: BSD-3-Clause OR GPL-3.0-only
 * Unprivileged, statically linked exit hook. No environment, shell or paths from
 * the request. The broker authenticates the kernel peer identity, not this token.
 */
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
int main(int argc, char **argv) {
    struct sockaddr_un address = { .sun_family = AF_UNIX };
    char request[66], answer;
    if (geteuid() == 0 || argc != 2 || strlen(argv[1]) != 64) return 75;
    for (int i=0; i<64; i++)
        if (!((argv[1][i]>='0' && argv[1][i]<='9') || (argv[1][i]>='a' && argv[1][i]<='f'))) return 75;
    /* Independent total deadline, including connect and short reads. */
    alarm(2);
    signal(SIGPIPE, SIG_IGN);
    strcpy(address.sun_path, "/run/zog-journal/socket");
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0 || connect(fd, (struct sockaddr*)&address, sizeof address)) return 75;
    memcpy(request, argv[1], 64); request[64]='\n';
    size_t sent=0;
    while(sent<65) { ssize_t n=write(fd,request+sent,65-sent); if(n<=0) return 75; sent+=(size_t)n; }
    int ok = read(fd, &answer, 1)==1 && answer=='1';
    close(fd);
    return ok ? 0 : 75;
}
