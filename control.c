#include <stdio.h>
#include <unistd.h>

#include <rte_common.h>
#include <rte_ip.h>
#include <rte_lpm.h>
#include <rte_lpm6.h>
#include <rte_ethdev.h>


#include <protobuf-c/protobuf-c.h>
#include <protobuf-c-rpc/protobuf-c-rpc.h>
#include <protobuf-c-rpc/protobuf-c-rpc-dispatch.h>

#include <router-dpdk/control.h>

#include "routing.h"
#include "router.pb-c.h"

#define UNUSED(x) x __attribute__((unused))



//void control__add_route4(Router_Service *,
//						 const AddRoute4Request *,
//						 AddRoute4Result_Closure, void *);
//void control__add_route6(Router_Service *,
//						 const AddRoute6Request *,
//						 AddRoute6Result_Closure, void *);
//void control__get_iface_status(Router_Service *,
//							   const GetIfaceRequest *,
//							   GetIfaceResult_Closure, void *);
//void control_error_handler(ProtobufC_RPC_Error_Code code,
//						   const char *message, void *error_func_data);




void control_args_listen(control_args_t * args, control_args_bind_t * bind,
						 int len)
{
	memcpy(&(args->bind), bind, sizeof(control_args_bind_t));
	args->backlog = len;
}

#define IPV6_TO_UINT8(x) \
  {(uint8_t) (x->networkaddr << 48) % 255,\
   (uint8_t) (x->networkaddr << 40) % 255,\
   (uint8_t) (x->networkaddr << 32) % 255,\
   (uint8_t) (x->networkaddr << 24) % 255,\
   (uint8_t) (x->networkaddr << 16) % 255,\
   (uint8_t) (x->networkaddr << 8)  % 255,\
   (uint8_t) (x->networkaddr)       % 255,\
   (uint8_t) (x->hostaddr << 48) % 255,\
   (uint8_t) (x->hostaddr << 40) % 255,\
   (uint8_t) (x->hostaddr << 32) % 255,\
   (uint8_t) (x->hostaddr << 24) % 255,\
   (uint8_t) (x->hostaddr << 16) % 255,\
   (uint8_t) (x->hostaddr << 8)  % 255,\
   (uint8_t) (x->hostaddr)       % 255}

//void control__add_route6(Router_Service * UNUSED(service),
//						 const AddRoute6Request * input,
//						 AddRoute6Result_Closure closure,
//						 void *closure_data)
//{
//	int socketid, ret;
//	AddRoute6Result res = ADD_ROUTE6_RESULT__INIT;
//	Cidr6 *cidr = input->cidr;
//	uint8_t ip[16] = IPV6_TO_UINT8(cidr->ip);
//
//	for (socketid = 0; socketid < NB_SOCKETS; socketid++) {
//		ret = rte_lpm6_add(ipv6_l3fwd_lookup_struct()[socketid],
//						   ip, cidr->length, input->port);
//		if (ret < 0) {
//			// TODO return error
//			rte_exit(EXIT_FAILURE, "Unable to add entry %u to the "
//					 "l3fwd LPM table on socket %d\n", socketid, socketid);
//		}
//	}
//
//	closure(&res, closure_data);
//}


static void control__add_route4(Router_Service * UNUSED(service),
						 const AddRoute4Request * input,
						 AddRoute4Result_Closure closure,
						 void *closure_data)
{
	int socketid;
	int ret;
	AddRoute4Result res = ADD_ROUTE4_RESULT__INIT;
	Cidr4 *cidr = input->cidr;

	if (input == NULL) {
		closure(NULL, closure_data);
		return;
	}

	for (socketid = 0; socketid < NB_SOCKETS; socketid++) {
		if (ipv4_l3fwd_lookup_struct[socketid] == NULL) {
			continue;
		}
		ret = rte_lpm_add(ipv4_l3fwd_lookup_struct[socketid],
						  cidr->ip, cidr->length, input->port);
		if (ret < 0) {
			// TODO return error
			rte_exit(EXIT_FAILURE, "Unable to add entry %u to the "
					 "l3fwd LPM table on socket %d\n", socketid, socketid);
		}
	}

	closure(&res, closure_data);
}

static void control__get_iface_status(Router_Service * UNUSED(service),
							   const GetIfaceRequest * input,
							   GetIfaceResult_Closure closure,
							   void *closure_data)
{
	int i;
	struct rte_eth_stats stats;
	GetIfaceResult res = GET_IFACE_RESULT__INIT;

	res.queue_stats = alloca(sizeof(QueueStats*) * RTE_ETHDEV_QUEUE_STAT_CNTRS);

	if (input == NULL) {
		closure(NULL, closure_data);
		return;
	}
	if (input->portid >= rte_eth_dev_count()) {
		closure(NULL, closure_data);
		return;
	}
	rte_eth_stats_get(input->portid, &stats);

	res.portid = input->portid;

	res.ipackets = stats.ipackets;
	res.opackets = stats.opackets;
	res.ibytes = stats.ibytes;
	res.obytes = stats.obytes;
	res.imissed = stats.imissed;
	res.ibadcrc = stats.ibadcrc;
	res.ibadlen = stats.ibadlen;
	res.ierrors = stats.ierrors;
	res.imcasts = stats.imcasts;
	res.rx_nombuf = stats.rx_nombuf;
	res.fdirmatch = stats.fdirmatch;
	res.fdirmiss = stats.fdirmiss;
	res.tx_pause_xon = stats.tx_pause_xon;
	res.rx_pause_xon = stats.rx_pause_xon;
	res.tx_pause_xoff = stats.tx_pause_xoff;
	res.rx_pause_xoff = stats.rx_pause_xoff;


	res.n_queue_stats = RTE_ETHDEV_QUEUE_STAT_CNTRS;

	for (i = 0; i < RTE_ETHDEV_QUEUE_STAT_CNTRS; i++) {
		res.queue_stats[i] = alloca(sizeof(QueueStats));
		queue_stats__init(res.queue_stats[i]);
		res.queue_stats[i]->ipackets = stats.q_ipackets[i];
		res.queue_stats[i]->opackets = stats.q_opackets[i];
		res.queue_stats[i]->ibytes   = stats.q_ibytes[i];
		res.queue_stats[i]->obytes   = stats.q_obytes[i];
		res.queue_stats[i]->errors   = stats.q_errors[i];
	}

	res.ilbpackets = stats.ilbpackets;
	res.olbpackets = stats.olbpackets;
	res.ilbbytes   = stats.ilbbytes;
	res.olbbytes   = stats.olbbytes;

	closure(&res, closure_data);
}

static void control_error_handler(ProtobufC_RPC_Error_Code UNUSED(code),
						   const char *message,
						   void *UNUSED(error_func_data))
{

	printf("ERROR: %s\n", message);
}

static struct _Router_Service router_service = ROUTER__INIT(control__);

void *control_main(void *argv)
{
//  int ret, sockfd, i, newsock;
//  fd_set active_fd_set, read_fd_set;
//
//  sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
//  if (sockfd < 0)
//      rte_exit(EXIT_FAILURE, "Couldn't create control socket\n");
//
//  ret = listen(sockfd, args->backlog);
//  if (ret != 0) {
//      perror("error listen on control socket");
//      rte_exit(EXIT_FAILURE, "Couldn't listen on socket control\n");
//  }
//
//  ret = bind(sockfd, (struct sockaddr *) &(args->bind), sizeof(args->bind));
//  if (ret != 0) {
//      perror("error binding control socket");
//      rte_exit(EXIT_FAILURE, "Error binding control socket\n");
//  }
//
//  FD_ZERO(&active_fd_set);
//  FD_SET(sockfd, &active_fd_set);
//
//  for (;;) {
//      read_fd_set = active_fd_set;
//      ret = select(FD_SETSIZE, &read_fd_set, NULL, NULL, NULL);
//      if (ret < 0) {
//          perror("error on select");
//          rte_exit(EXIT_FAILURE, "Error on select control socket\n");
//      }
//
//      for (i = 0; i < FD_SETSIZE; i++) {
//          if (FD_ISSET(i, &read_fd_set)) {
//              if (i == sockfd) {
//                  /* This is a new connection */
//                  newsock = accept(sockfd, (struct sockaddr *) &(args->bind), (socklen_t*) sizeof(control_args_bind_t));
//                  if (newsock < 0) {
//                      //failure
//                      //TODO: log this somewhere
//                      continue;
//                  }
//                  FD_SET(newsock, &active_fd_set);
//              } else {
//                  if (control_handle_socket(i) < 0) {
//                      close(i);
//                      FD_CLR(i, &active_fd_set);
//                  }
//              }
//          }
//      }
//  }
	control_args_t *UNUSED(args) = (control_args_t *) argv;
	ProtobufC_RPC_Server *server;
	ProtobufC_RPC_AddressType address_type = PROTOBUF_C_RPC_ADDRESS_LOCAL;
	const char *name = "/tmp/truc.sock";

	server =
		protobuf_c_rpc_server_new(address_type, name,
								  (ProtobufCService *) & router_service,
								  NULL);
	protobuf_c_rpc_server_set_error_handler(server, &control_error_handler,
											NULL);

	for (;;)
		protobuf_c_rpc_dispatch_run(protobuf_c_rpc_dispatch_default());

	protobuf_c_rpc_server_destroy(server, 0);

	return NULL;
}
