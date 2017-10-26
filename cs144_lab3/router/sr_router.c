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

/*retrieve icmp header*/
sr_icmp_hdr_t *retrieve_icmp_hdr(uint8_t *packet)
{
    return (sr_icmp_hdr_t *)(packet + sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t));
}

/*retrieve icmp t3 header*/
sr_icmp_t3_hdr_t *retrieve_icmp_t3_hdr(uint8_t *packet)
{
    return (sr_icmp_t3_hdr_t *)(packet + sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t));
}

void send_icmp_packet(struct sr_instance *sr, uint8_t *packet, unsigned int len,
                             char *receiving_interface, uint8_t icmp_type, uint8_t icmp_code, struct sr_if *destination_interface)

{    
    
    int outgoing_len = len;
    sr_ethernet_hdr_t *original_ethernet_header = retrieve_ethernet_hdr(packet);
    sr_ip_hdr_t *original_ip_header = retrieve_ip_hdr(packet);
    struct sr_if *outgoing_interface = sr_get_interface(sr, receiving_interface);
    uint32_t source_ip = outgoing_interface->ip;
    
    if (icmp_type == 0) { /* Send back original data with headers if type 0 */
        
        uint8_t *sent_icmp_packet = (uint8_t *)malloc(outgoing_len);
        sr_icmp_hdr_t *send_icmp_header = retrieve_icmp_hdr(sent_icmp_packet);
        
        memset(sent_icmp_packet, 0, sizeof(uint8_t) * outgoing_len);
        sr_ip_hdr_t *send_ip_header = retrieve_ip_hdr(sent_icmp_packet);
        sr_ethernet_hdr_t *send_ethernet_header = retrieve_ethernet_hdr(sent_icmp_packet);
        if (destination_interface) { /* Check if the packet was destined for an interface other than the one it came in on */
            source_ip = destination_interface->ip;
        }
        /* Copying ICMP metadata into new ICMP header for type 0 */
        fprintf(stderr, "Outgoing ICMP is type 0. Copying original ICMP header into outgoing ICMP header\n");
        memcpy(send_icmp_header, retrieve_icmp_hdr(packet), outgoing_len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
        send_icmp_header->icmp_code = icmp_code;
        send_icmp_header->icmp_type = icmp_type;
        send_icmp_header->icmp_sum = 0;
        
        /* Calculate cksum for header + data if type 0 */
        send_icmp_header->icmp_sum = cksum(send_icmp_header, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
        
        /*Prepare IP Header*/
        memcpy(send_ip_header, original_ip_header, sizeof(sr_ip_hdr_t));
        send_ip_header->ip_ttl = 64;
        send_ip_header->ip_p = ip_protocol_icmp;
        send_ip_header->ip_dst = original_ip_header->ip_src;
        send_ip_header->ip_len = htons(outgoing_len - sizeof(sr_ethernet_hdr_t));
        send_ip_header->ip_src = source_ip;
        send_ip_header->ip_sum = 0;
        send_ip_header->ip_sum = cksum(send_ip_header, sizeof(sr_ip_hdr_t));

        /*Prepare Ethernet Header*/
        memcpy(send_ethernet_header->ether_shost, outgoing_interface->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);
        memcpy(send_ethernet_header->ether_dhost, original_ethernet_header->ether_shost, sizeof(uint8_t) * ETHER_ADDR_LEN);
 
        send_ethernet_header->ether_type = htons(ethertype_ip);
        print_hdr_eth(sent_icmp_packet);
        print_hdr_ip(sent_icmp_packet + sizeof(sr_ethernet_hdr_t));
        print_hdr_icmp(sent_icmp_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

        sr_send_packet(sr, sent_icmp_packet, outgoing_len, receiving_interface);
        free(sent_icmp_packet);
    
    }
    else { /* Send back only headers if not type 0 */
        printf("sr_icmp hdr length: %lu\n", sizeof(sr_icmp_hdr_t));
        printf("sr_icmp t3 hdr length: %lu\n", sizeof(sr_icmp_t3_hdr_t));

        outgoing_len = sizeof(sr_icmp_t3_hdr_t) + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t);
        uint8_t *sent_icmp_packet = (uint8_t *)malloc(outgoing_len);
        
        sr_icmp_t3_hdr_t *send_icmp_header = retrieve_icmp_t3_hdr(sent_icmp_packet);

        memset(sent_icmp_packet, 0, sizeof(uint8_t) * outgoing_len);
        sr_ip_hdr_t *send_ip_header = retrieve_ip_hdr(sent_icmp_packet);
        sr_ethernet_hdr_t *send_ethernet_header = retrieve_ethernet_hdr(sent_icmp_packet);
        if (destination_interface) { /* Check if the packet was destined for an interface other than the one it came in on */
	printf("helloi\n");
            source_ip = destination_interface->ip;
        }
        /*Copying 28 bytes of IP Header into icmp header for type 11 or type 3*/
        /*To check*/
        memcpy(send_icmp_header->data, original_ip_header, sizeof(sr_ip_hdr_t)+8);/*ICMP_DATA_SIZE);*/
        send_icmp_header->icmp_code = icmp_code;
        send_icmp_header->icmp_type = icmp_type;
        send_icmp_header->unused = 0;
        send_icmp_header->next_mtu = 0;
        send_icmp_header->icmp_sum = 0;
        /* Calculate cksum for header only if not type 0 */
        send_icmp_header->icmp_sum = cksum(send_icmp_header, sizeof(sr_icmp_t3_hdr_t));

        send_icmp_header->icmp_sum = cksum(send_icmp_header, outgoing_len - sizeof(sr_ethernet_hdr_t)-sizeof(sr_ip_hdr_t));
        /*Prepare IP Header*/
        memcpy(send_ip_header, original_ip_header, sizeof(sr_ip_hdr_t));
        send_ip_header->ip_ttl = 64;
        send_ip_header->ip_p = ip_protocol_icmp;
        send_ip_header->ip_dst = original_ip_header->ip_src;
        send_ip_header->ip_len = htons(outgoing_len - sizeof(sr_ethernet_hdr_t));
        send_ip_header->ip_src = source_ip;
        send_ip_header->ip_id = 0;
        send_ip_header->ip_sum = 0;
        send_ip_header->ip_sum = cksum(send_ip_header, sizeof(sr_ip_hdr_t));

        /*Prepare Ethernet Header*/
        memcpy(send_ethernet_header->ether_shost, outgoing_interface->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);
        memcpy(send_ethernet_header->ether_dhost, original_ethernet_header->ether_shost, sizeof(uint8_t) * ETHER_ADDR_LEN);

        send_ethernet_header->ether_type = htons(ethertype_ip);

        print_hdr_eth(sent_icmp_packet);
        print_hdr_ip(sent_icmp_packet + sizeof(sr_ethernet_hdr_t));
        print_hdr_icmp(sent_icmp_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

        printf("icmp t3 sent\n");
        sr_send_packet(sr, sent_icmp_packet, outgoing_len, receiving_interface);
        free(sent_icmp_packet);
    }    
  
    return;
}

struct sr_if *get_interface_from_ip(struct sr_instance *sr, uint32_t ip_address)
{
    struct sr_if *current_interface = sr->if_list;
    struct sr_if *dest_interface = NULL;
    while (current_interface) {
        if (ip_address == current_interface->ip) { /* left, none */
            dest_interface = current_interface;
            break;
        }
        current_interface = current_interface->next;
    }
    return dest_interface;
}

struct sr_if *get_interface_from_eth(struct sr_instance *sr, uint8_t *eth_address)
{
    struct sr_if *current_interface = sr->if_list;
    struct sr_if *dest_interface = NULL;
    short match_found = 0;
    while (current_interface) {
        match_found = 1;
        int i=0;
        for (i = 0; i < ETHER_ADDR_LEN; i++) {
            if (current_interface->addr[i] != eth_address[i]) {
                match_found = 0;
                break;
            }
        }
        if (match_found) {
            fprintf(stderr, "A matching interface is found based on the ethernet address.\n");
            dest_interface = current_interface;
            break;
        }
        current_interface = current_interface->next;
    }
    return dest_interface;
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

    if (len <(sizeof(sr_arp_hdr_t) + sizeof(sr_ethernet_hdr_t))) {
        fprintf(stderr, "Error: This is an invalid arp packet because of the length.\n");
        return;
    }


    sr_arp_hdr_t *received_arp_hdr = retrieve_arp_hdr(packet);  
    struct sr_if *router_if = sr_get_interface(sr, interface);
    /*handle arp request*/
    if (received_arp_hdr->ar_op == htons(arp_op_request)){
        printf("arp packet\n");
        /*comapre the ip address of router's interface and the ip address of arp request'
        interface*/

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
            /* send arp reply back*/
            sr_ethernet_hdr_t *received_ethernet_hdr = retrieve_ethernet_hdr(packet);
            
            /*construct the ethernet header(arp reply)*/
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
            printf("This packet is sent to the other routers, just drop it\n");
            return;
        }

    }
    /*handle ARP rely*/
    else if (arp_op_reply == ntohs(received_arp_hdr->ar_op)) { 
        fprintf(stderr, "Received ARP reply on interface %s\n", interface);

        struct sr_arpreq *cached_arp_request = sr_arpcache_insert(&(sr->cache),
                                               received_arp_hdr->ar_sha,
                                               received_arp_hdr->ar_sip);
        if (cached_arp_request) {
            fprintf(stderr, "Sending packets that were waiting on ARP reply...\n");
            struct sr_packet *waiting_packet = cached_arp_request->packets;
            while (waiting_packet) { /* Send all packets waiting on this ARP request*/
                uint8_t *send_packet = waiting_packet->buf;
                sr_ethernet_hdr_t *send_ethernet_header = retrieve_ethernet_hdr(send_packet);
                memcpy(send_ethernet_header->ether_dhost, received_arp_hdr->ar_sha, ETHER_ADDR_LEN);
                memcpy(send_ethernet_header->ether_shost, router_if->addr, ETHER_ADDR_LEN);
                sr_send_packet(sr, send_packet, waiting_packet->len, interface);
                waiting_packet = waiting_packet->next;
            }
            sr_arpreq_destroy(&(sr->cache), cached_arp_request);
        }
    } 
    return;

}

struct sr_rt *calculate_LPM(struct sr_instance *sr, uint32_t destination_ip)
{
    struct sr_rt *current_routing_table = sr->routing_table;
    struct sr_rt *best = NULL;
     
    while (current_routing_table) {
        if ((current_routing_table->dest.s_addr & current_routing_table->mask.s_addr) == (destination_ip & current_routing_table->mask.s_addr)) {
            if (!best || (current_routing_table->mask.s_addr > best->mask.s_addr)) {
                best = current_routing_table;
            }
        }
        current_routing_table = current_routing_table->next;
    }
    return best;
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

    /*checksum sanity-check*/
    sr_ip_hdr_t *received_ip_hdr = retrieve_ip_hdr(packet); 

    uint16_t received_ip_hdr_sum = received_ip_hdr->ip_sum;
    received_ip_hdr->ip_sum = 0;

    uint16_t computed_ip_hdr_sum = cksum(received_ip_hdr, sizeof(sr_ip_hdr_t));

    if (received_ip_hdr_sum == computed_ip_hdr_sum){
        received_ip_hdr->ip_sum = computed_ip_hdr_sum;
    }
    else{
        printf("ip_sum: %d\n", received_ip_hdr_sum);
        printf("computed ip_sum: %d\n", computed_ip_hdr_sum);
        fprintf(stderr, "IP checksum is wrong\n");
        return;
    } 

    if((received_ip_hdr -> ip_ttl) < 1){
        printf("ttl error: the ttl is expired\n");
        send_icmp_packet(sr, packet, len, interface, 11, 0, NULL);
        return;
    }

    /* Check if this packet is destined for one of the interfaces of the router*/
    printf("received ip: %d\n", received_ip_hdr->ip_dst);
    struct sr_if *dest_if = get_interface_from_ip(sr, received_ip_hdr->ip_dst);
    if (dest_if){
 
        if((received_ip_hdr -> ip_ttl) < 1){
            printf("ttl error: the ttl is expired\n");
            send_icmp_packet(sr, packet, len, interface, 11, 0, NULL);
            return;
        }
        if (received_ip_hdr->ip_p == ip_protocol_icmp) {
            if (len < (sizeof(sr_icmp_hdr_t) + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t))) {
                fprintf(stderr, "Error! This ICMP packet is not valid because of the length.\n");
                return;
            }
            sr_icmp_hdr_t *received_icmp_hdr = retrieve_icmp_hdr(packet);
            if (received_icmp_hdr->icmp_type != 8) {
                fprintf(stderr, "Error, this is not an echo request\n");
                return;
            }

            uint16_t received_icmp_hdr_sum = received_icmp_hdr->icmp_sum;
            received_icmp_hdr->icmp_sum = 0;
            uint16_t computed_icmp_hdr_sum = cksum(received_icmp_hdr,len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t)); 
            
            if (received_icmp_hdr_sum == computed_icmp_hdr_sum){
                received_icmp_hdr->icmp_sum = computed_icmp_hdr_sum;
            }
            else{
                printf("icmp header checksum: %d\n", received_icmp_hdr_sum);
                printf("computed icmp header checksum: %d\n", computed_icmp_hdr_sum);
                fprintf(stderr, "ICMP checksum is wrong\n");
                return;
            }  

            send_icmp_packet(sr, packet, len, interface, 0, 0, dest_if);
            return;
         }
         else {  /*Packet is not ICMP.*/
            send_icmp_packet(sr, packet, len, interface, 3, 3, dest_if);
            return;
        }

    }
    /*forwarding this packet to the others*/
    else{
        /*length sanity-check*/ 
        if (len < (sizeof(sr_arp_hdr_t) + sizeof(sr_ethernet_hdr_t))){
            printf("size error: the size of the packet doesn't match the minimum of the valid packet\n");
            return;
        } 
 
        if((received_ip_hdr -> ip_ttl) < 2){
            printf("ttl error: the ttl is expired\n");
            send_icmp_packet(sr, packet, len, interface, 11, 0, NULL);
            return;
        }

        /*decrease the ttl*/
        printf("ip header's ttl: %d\n", received_ip_hdr -> ip_ttl);
        received_ip_hdr -> ip_ttl = received_ip_hdr -> ip_ttl - 1;
        printf("ip header's ttl: %d\n", received_ip_hdr -> ip_ttl); 

        /*recompute the checksum*/
        received_ip_hdr->ip_sum = 0;
        received_ip_hdr->ip_sum = cksum(received_ip_hdr, sizeof(sr_ip_hdr_t));
 
        /*match the ip prefix*/
        uint32_t ip_packet_dest = received_ip_hdr->ip_dst; 
        struct sr_rt * best = calculate_LPM(sr, ip_packet_dest);
        if (best == NULL){
            printf("The ip doesn't belong to this router!\n");
            send_icmp_packet(sr, packet, len, interface, 3, 0, NULL);
            return;
        }

        struct sr_arpentry *next_hop_mac = sr_arpcache_lookup(&(sr->cache), best->gw.s_addr);
        if (!next_hop_mac) { /* No ARP cache entry found */
            printf("No ARP cache is found.\n");
            struct sr_arpreq *queued_arp_request = sr_arpcache_queuereq(&(sr->cache), best->gw.s_addr, packet, len, best->interface);
            handle_arpreq(sr, queued_arp_request);
            return;
        }

        /*forwading the packet*/
        sr_ethernet_hdr_t *send_ethernet_hdr = retrieve_ethernet_hdr(packet);
        memcpy(send_ethernet_hdr->ether_shost, sr_get_interface(sr, best->interface)->addr, sizeof(uint8_t) * ETHER_ADDR_LEN);
        memcpy(send_ethernet_hdr->ether_dhost, next_hop_mac->mac, sizeof(uint8_t) * ETHER_ADDR_LEN);
        free(next_hop_mac);
        printf("Going to forward the packet\n");
        sr_send_packet(sr, packet, len, sr_get_interface(sr, best->interface)->name);
        return;

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

