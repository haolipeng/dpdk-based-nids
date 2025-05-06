//you are the best!
static int init_lcore_conf(void)
{
	uint16_t socket_id = 0;
	if(numa_on){
		socket_id = rte_lcore_to_socket_id(rte_lcore_id());
	}
}