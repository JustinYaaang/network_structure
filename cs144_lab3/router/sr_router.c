/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */


/*retrieve arp header*/
sr_arp_hdr_t *retrieve_arp_hdr(uint8_t *packet)
{
    return (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
}

/*retrieve ip header*/
sr_ip_hdr_t *retrieve_ip_hdr(uint8_t *packet)
{
    return (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
}


/*retrieve ethernet header*/
sr_ethernet_hdr_t *retrieve_ethernet_hdr(uint8_t *packet)
{
    return (sr_ethernet_hdr_t *)packet;
}


/*---------------------------------------------------------------------
 * Method: sr_handle_arp_packet(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a arp packet on the
 * interface.
 *---------------------------------------------------------------------*/

void  sr_handle_arp_packet(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
    sr_arp_hdr_t *received_arp_hdr = retrieve_arp_hdr(packet);  
    /*handle arp request*/
    if (received_arp_hdr->ar_op == htons(arp_op_request)){
        printf("arp packet\n");
        /*comapre the ip address of router's interface and the ip address of arp request'
        interface*/

        struct sr_if *router_if = sr_get_interface(sr, interface);
        uint32_t ar_target_ip = received_arp_hdr -> ar_tip;  		
        uint32_t router_ip = router_if -> ip;  		
        printf("taget ip: %d\n", ar_target_ip);

        int router_found = 0; 
        while (router_if != NULL){ 
            printf("router ip: %d\n", router_if->ip);
            if (ar_target_ip == router_ip){
                router_found = 1;
                break;
            }
            router_if = router_if->next;
            
        } 

        if (router_found > 0){
            printf("the target ip of the arp request is the router's ip\n");
           
            /* send arp reply back*/
            sr_ethernet_hdr_t *received_ethernet_hdr = retrieve_ethernet_hdr(packet);
            
            /*construct the ethernet header*/
            sr_ethernet_hdr_t * arp_reply_hdr = (sr_ethernet_hdr_t *) malloc(sizeof(sr_ethernet_hdr_t)); 
            memcpy(arp_reply_hdr->ether_dhost, received_ethernet_hdr->ether_shost, ETHER_ADDR_LEN); 
            memcpy(arp_reply_hdr->ether_shost,router_if-> addr, ETHER_ADDR_LEN); 
            arp_reply_hdr->ether_type = htons(ethertype_arp); 

            /*construct the ethernet body(arp header)*/
            sr_arp_hdr_t * arp_reply_body = (sr_arp_hdr_t *) malloc(sizeof(sr_arp_hdr_t));       
            memcpy(arp_reply_body, received_arp_hdr, sizeof(sr_arp_hdr_t)); 
            arp_reply_body -> ar_op = htons(arp_op_reply); 
            memcpy(arp_reply_body->ar_sha, router_if-> addr, ETHER_ADDR_LEN); 
            arp_reply_body -> ar_sip = router_ip; 
            memcpy(arp_reply_body->ar_tha, received_ethernet_hdr->ether_shost, ETHER_ADDR_LEN); 
            arp_reply_body -> ar_tip = received_arp_hdr -> ar_sip; 

            /*construct the ethernet packet(arp reply)*/
            uint8_t * arp_reply_packet = (uint8_t *) malloc(sizeof(sr_ethernet_hdr_t)+sizeof(sr_arp_hdr_t));       
            memcpy(arp_reply_packet, arp_reply_hdr, sizeof(sr_ethernet_hdr_t));
            memcpy(arp_reply_packet+sizeof(sr_ethernet_hdr_t), arp_reply_body, sizeof(sr_arp_hdr_t));

            sr_send_packet(sr, arp_reply_packet, len, interface);
            free(arp_reply_hdr);
            free(arp_reply_body);
            free(arp_reply_packet);

        }
        else{
            printf("send to the other routersi\n");
        }

    }    
    return;


}

/*---------------------------------------------------------------------
 * Method: sr_handle_ip_packet(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives an ip packet on the
 * interface.
 *---------------------------------------------------------------------*/

void  sr_handle_ip_packet(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{

    /*length sanity-check*/ 
    if (len < (sizeof(sr_arp_hdr_t) + sizeof(sr_ethernet_hdr_t))){
        printf("size error: the size of the packet doesn't match the minimum of the valid packet\n");
        return;
    } 
    else{
        /*decrease the ttl*/
        sr_ip_hdr_t *received_ip_hdr = retrieve_ip_hdr(packet);  
        printf("ip header's ttl: %d\n", received_ip_hdr -> ip_ttl);
        received_ip_hdr -> ip_ttl = received_ip_hdr -> ip_ttl - 1;
        printf("ip header's ttl: %d\n", received_ip_hdr -> ip_ttl); 
 
        /*match the ip prefix*/
        uint32_t ip_packet_dest = received_ip_hdr->ip_dst; 
        printf("ip packet dest: %d\n", ip_packet_dest);
        struct sr_rt * routing_table = sr -> routing_table;        
        while (routing_table != NULL){
            struct in_addr if_ip_dest_addr = routing_table->dest;
            char *if_ip_dest = inet_ntoa(if_ip_dest_addr);
            printf("interface ip dest:%s\n", if_ip_dest);


            routing_table = routing_table -> next;
        }

    }
  



}


/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);
  
  /* fill in code here */
  /*check interface first*/
	

  /*handle arp request and reply*/ 
  if (ethertype(packet) == ethertype_arp){
    sr_handle_arp_packet(sr, packet, len, interface);
  }
  else if (ethertype(packet) == ethertype_ip){
    printf("ip packet\n");
    sr_handle_ip_packet(sr, packet, len, interface);
  }



}/* end sr_ForwardPacket */

