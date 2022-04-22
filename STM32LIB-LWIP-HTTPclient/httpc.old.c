#include "httpc_platform.h"
#include "string.h"

static struct tcp_pcb *pcb_client;

uint16_t nWritten = 0; //write buffer index

static err_t tcp_callback_connected(void *arg, struct tcp_pcb *pcb_new, err_t err);
static err_t tcp_callback_sent(void *arg, struct tcp_pcb *tpcb, u16_t len);
static err_t tcp_callback_recv(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err);
static err_t tcp_callback_poll(void *arg, struct tcp_pcb *tpcb);
static void tcp_callback_error(void *arg, err_t err);

static void app_open_conn(void)
{
    ip_addr_t server_addr;
    err_t err;

    if (pcb_client == NULL)
    {
        pcb_client = tcp_new();
        if (pcb_client == NULL) //lack of memory
        {
            memp_free(MEMP_TCP_PCB, pcb_client);
            pcb_client = NULL;
            HAL_GPIO_WritePin(LD2_GPIO_Port, LD2_Pin, GPIO_PIN_SET); //error led
        }
    }

    IP4_ADDR(&server_addr,  SERVER_IP_ADDR0,
                            SERVER_IP_ADDR1,
                            SERVER_IP_ADDR2,
                            SERVER_IP_ADDR3); 
    err = tcp_connect(pcb_client, &server_addr, SERVER_PORT, tcp_callback_connected); //connect

    if(err == ERR_ISCONN) //already connected
    {
        app_close_conn();
    }
}

static void app_send_data(void *pData, u16_t len)
{
    nWritten = 0; //clear index
    tcp_write(pcb_client, &pData, len, 0); //use pointer, should not changed until receive ACK
}

static err_t tcp_callback_connected(void *arg, struct tcp_pcb *pcb_new, err_t err)
{
    LWIP_UNUSED_ARG(arg);

    if (err != ERR_OK) //error when connect to the server
    {
        return err;
    }

    tcp_setprio(pcb_new, TCP_PRIO_NORMAL); //set priority for the client pcb

    tcp_arg(pcb_new, 0); //no argument is used
    tcp_sent(pcb_new, tcp_callback_sent); //register send callback
    tcp_recv(pcb_new, tcp_callback_recv);  //register receive callback
    tcp_err(pcb_new, tcp_callback_error); //register error callback
    tcp_poll(pcb_new, tcp_callback_poll, 0); //register poll callback

    app_send_data(); //send a request

    return ERR_OK;
}

static err_t tcp_callback_sent(void *arg, struct tcp_pcb *tpcb, u16_t len)
{
    LWIP_UNUSED_ARG(arg);
    LWIP_UNUSED_ARG(tpcb);
    LWIP_UNUSED_ARG(len);

    nWritten += len;

    /* Need to flush remaining data */
    if(nWritten < sizeof(struct time_packet))
    {
        tcp_output(pcb_client); //flush
    }
    /* Invalid length of sent data */
    else if(nWritten > sizeof(struct time_packet))
    {
        HAL_GPIO_WritePin(LD2_GPIO_Port, LD2_Pin, GPIO_PIN_SET); //error led
        app_close_conn();
    }
    /* Success! */
    else
    {
        HAL_GPIO_TogglePin(LD3_GPIO_Port, LD3_Pin); //blink green when sent O.K
    }

    return ERR_OK;
}

static err_t tcp_callback_recv(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err)
{
    err_t ret_err;

    /* Session is closed */
    if (p == NULL)
    {
        app_close_conn();
        ret_err = ERR_OK;
    }
    /* tcp_abort is called */
    else if (err != ERR_OK)
    {
        tcp_recved(tpcb, p->tot_len); //advertise window size
        pbuf_free(p);
        ret_err = err;
    }
    /* Receiving data */
    else
    {
        tcp_recved(tpcb, p->tot_len); //advertise window size

        memcpy(&packet + nRead, p->payload, p->len);
        nRead += p->len;

        /**/
        if(nRead == sizeof(struct time_packet) && packet.type == RESP) //if received length is valid
        {
            nRead = 0;

            printf("%04d-%02d-%02d %02d:%02d:%02d\n",
            packet.year + 2000,
            packet.month, packet.day, packet.hour, packet.minute, packet.second); //print time information

            app_close_conn(); //close connection
        }
        else if(nRead > sizeof(struct time_packet))
        {
            nRead = 0;
            app_close_conn(); //close connection
        }

        pbuf_free(p); //free pbuf
        ret_err = ERR_OK;
    }

    return ret_err;
}

static void app_close_conn(void)
{
    /* clear callback functions */
    tcp_arg(pcb_client, NULL);
    tcp_sent(pcb_client, NULL);
    tcp_recv(pcb_client, NULL);
    tcp_err(pcb_client, NULL);
    tcp_poll(pcb_client, NULL, 0);

    tcp_close(pcb_client);    //close connection
    pcb_client = NULL;
}

static void tcp_callback_error(void *arg, err_t err)
{
    LWIP_UNUSED_ARG(arg);
    LWIP_UNUSED_ARG(err);

    HAL_GPIO_WritePin(LD2_GPIO_Port, LD2_Pin, GPIO_PIN_SET); //error led
}

static err_t tcp_callback_poll(void *arg, struct tcp_pcb *tpcb)
{
    return ERR_OK;
}

void HTTPC_Run(void)
{
    ethernetif_input(&gnetif);
    sys_check_timeouts();
    ethernetif_set_link(&gnetif);
}

void ethernetif_notify_conn_changed(struct netif *netif)
{
    if (netif_is_link_up(netif))
    {
        HAL_GPIO_WritePin(LD3_GPIO_Port, LD3_Pin, GPIO_PIN_SET);
    }
    else
    {
        HAL_GPIO_WritePin(LD3_GPIO_Port, LD3_Pin, GPIO_PIN_RESET);
    }
}
