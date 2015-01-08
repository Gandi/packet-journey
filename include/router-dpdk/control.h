
#include <sys/un.h>
#include <sys/socket.h>

typedef struct sockaddr_un control_args_bind_t;

typedef struct control_args {
	control_args_bind_t bind;
	socklen_t socklen;
	int backlog;
} control_args_t;

void control_args_listen(control_args_t *, control_args_bind_t *, int);

void * control_main(void *);


