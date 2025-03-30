/**********************************************************************
 * file:  sr_router.c
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
 #include <string.h>
 #include <unistd.h>
 #include <stdlib.h>
 
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
   if (len < sizeof(sr_ethernet_hdr_t)) {
     fprintf(stderr, "Error: Ethernet frame too short\n");
   }
 
   uint16_t ethtype = ethertype(packet);
 
   if (ethtype == ethertype_ip) {
     handle_ip_packet(sr, packet, len, interface);
   } else if (ethtype == ethertype_arp) {
     handle_arp_packet(sr, packet, len, interface);
   } else {
     fprintf(stderr, "Unknown Ethernet type; dropping packet\n");
   }
 
 } /* end sr_handlepacket */
 
 
 /* Add any additional helper methods here & don't forget to also declare
 them in sr_router.h.
 
 If you use any of these methods in sr_arpcache.c, you must also forward declare
 them in sr_arpcache.h to avoid circular dependencies. Since sr_router
 already imports sr_arpcache.h, sr_arpcache cannot import sr_router.h -KM */
 
 void handle_ip_packet(struct sr_instance* sr, uint8_t *packet, unsigned int len, char* interface) {
   if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) {
     fprintf(stderr, "error: IP packet is too short\n");
     return;
   }
 
   // get IP header.
   sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));
 
   // verify IP checksum
   uint16_t received_cksum = ip_hdr->ip_sum;
   ip_hdr->ip_sum = 0; // reset checksum for calculation
   if (cksum(ip_hdr, sizeof(sr_ip_hdr_t)) != received_cksum) {
     fprintf(stderr, "error: Invalid IP header checksum\n");
     return;
   }
 
   // check if destination IP matches one of the router's interfaces
   struct sr_if *dest_iface = get_interface_from_ip(sr, ip_hdr->ip_dst);
   if (dest_iface) {
     // packet is destined for one of the router's interfaces
     if (ip_hdr->ip_p == ip_protocol_icmp) {
       // handle ICMP packet
       handle_icmp_packet(sr, packet, len, interface);
     } else {
       // send ICMP port unreachable (type 3, code 3)
       send_icmp_message(sr, packet, len, 3, 3, interface);
      }
   } else {
     // packet is not for us -- forward it.
     forward_ip_packet(sr, packet, len, interface);
   }
 }

 void forward_ip_packet(struct sr_instance* sr, uint8_t *packet, unsigned int len, char* interface) {
  /* Decrement TTL and recompute checksum */
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  if (ip_hdr->ip_ttl <= 1) {
      /* TTL expired, send ICMP Time Exceeded */
      send_icmp_message(sr, packet, len, 11, 0, interface);
      return;
  }

  ip_hdr->ip_ttl--;
  ip_hdr->ip_sum = 0;
  ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

  /* Longest prefix match for next hop */
  struct sr_rt *rt_entry = longest_prefix_match(sr, ip_hdr->ip_dst);
  if (!rt_entry) {
      /* No match, send ICMP Destination Net Unreachable */
      send_icmp_message(sr, packet, len, 3, 0, interface);
      return;
  }

  /* Check ARP cache for next-hop MAC address */
  struct sr_arpentry *arp_entry = sr_arpcache_lookup(&(sr->cache), rt_entry->gw.s_addr);
  if (arp_entry) {
      /* Send packet if MAC address is available */

      // get Ethernet header.
      sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;

      // Set destination MAC to the ARP entry obtained.
      memcpy(eth_hdr->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);

      // Set source MAC to the MAC addr of the outgoing interface.
      memcpy(eth_hdr->ether_shost, sr_get_interface(sr, rt_entry->interface)->addr, ETHER_ADDR_LEN);

      // send the packet to outgoing interface.
      sr_send_packet(sr, packet, len, rt_entry->interface);
      free(arp_entry);
  } 
  else {
      /* Queue packet and send ARP request */
      // the Ethernet header is filled in with the correct source MAC.
      //      rt_entry->interface is the interface through which we sent out ARP req, and through which ARP reply comes back.
      //      THIS interface's MAC is the source MAC.
      // so when we dequeue and send it out, only need to modify the destination.
      //  This is done in handle_arp_packet() below, with "memcpy"
      struct sr_arpreq *req = sr_arpcache_queuereq(&(sr->cache), rt_entry->gw.s_addr, packet, len, rt_entry->interface);
      handle_arpreq(sr, req);
  }
}


void send_arp_reply(struct sr_instance *sr, sr_arp_hdr_t *arp_hdr, struct sr_if *iface) {
  uint8_t *arp_reply = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));

  /* Fill Ethernet header */
  sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)arp_reply;
  memcpy(eth_hdr->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
  memcpy(eth_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
  eth_hdr->ether_type = htons(ethertype_arp);

  /* Fill ARP header */
  sr_arp_hdr_t *reply_hdr = (sr_arp_hdr_t *)(arp_reply + sizeof(sr_ethernet_hdr_t));
  reply_hdr->ar_hrd = htons(arp_hrd_ethernet);
  reply_hdr->ar_pro = htons(ethertype_ip);
  reply_hdr->ar_hln = ETHER_ADDR_LEN;
  reply_hdr->ar_pln = 4;
  reply_hdr->ar_op = htons(arp_op_reply);
  memcpy(reply_hdr->ar_sha, iface->addr, ETHER_ADDR_LEN);
  reply_hdr->ar_sip = iface->ip;
  memcpy(reply_hdr->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
  reply_hdr->ar_tip = arp_hdr->ar_sip;

  /* Send ARP reply */
  sr_send_packet(sr, arp_reply, sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t), iface->name);
  free(arp_reply);
}



void handle_arp_packet(struct sr_instance* sr, uint8_t *packet, unsigned int len, char* interface) {
  // validate packet length
  if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t)) {
    fprintf(stderr, "Error: ARP packet too short\n");
    return;
  }

  // get ARP header -- skip Ethernet header (first 14 bytes)
  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

  // ARP Header relevant fields:
  //  ar_op: opcode -- either request or reply
  //  ar_tip: Target IP address in the ARP request. (ultimate destination of ARP packet)
  //  ar_sha: Sender's Hardware Address (MAC address)
  //  ar_sip: Senders IP addres

  // check if ARP request or reply.
  //  ntohs: Convert ARP opcode (ar_op) from network byte order to host byte order.
  if (ntohs(arp_hdr->ar_op) == arp_op_request) {
    //ARP request: Check if it's one of our IPs that is being requested.
    //  iface is the interface the packet came in on.
    struct sr_if *iface = sr_get_interface(sr, interface);

    // if iface's IP is the target IP of the received request, then
    //  the ARP req was asking for iface, which has one of our router's IP addresses.
    //  I.E. we must send a reply providing our MAC address.
    if (iface->ip == arp_hdr->ar_tip) {
      // send ARP reply
      send_arp_reply(sr, arp_hdr, iface);
    }
    // otherwise, it's not one of our IPs, so do nothing.

  } else if (ntohs(arp_hdr->ar_op) == arp_op_reply) {
    // ARP reply: Update ARP cache and process queued packets.
    //  Insert a new mapping to the ARP cache:
    //  ar_sha --> sender's MAC address, in the ARP reply received.
    //  ar_sip --> sender's IP address
    struct sr_arpreq *req = sr_arpcache_insert(&(sr->cache), arp_hdr->ar_sha, arp_hdr->ar_sip);
    // sr_arpcache_insert ALSO returns packet(s) waiting on that MAC address to be sent to the IP address if any were already in the cache; else NULL.
    
    // there were packets waiting to be sent to the sender's IP addr, so send them out now through the newly found MAC address.
    if (req) {
      // send queued packets.
      struct sr_packet *waiting_packet = req->packets;
    
      while (waiting_packet) {
        /* Update the destination MAC in the Ethernet frame */
        sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)waiting_packet->buf;

        // Source: the router's MAC. This remains unchanged.
        // update destination: From whatever it was, to the received MAC address.
        memcpy(eth_hdr->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);

        /* Send the queued packet */
        sr_send_packet(sr, waiting_packet->buf, waiting_packet->len, waiting_packet->iface);
        waiting_packet = waiting_packet->next;
      }
      /* Destroy the request after sending all queued packets */
      sr_arpreq_destroy(&(sr->cache), req);
    }
  }
}


void handle_icmp_packet(struct sr_instance* sr, uint8_t *packet, unsigned int len, char* interface) {
  /* Validate minimum length for Ethernet + IP + ICMP header */
  if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t)) {
      fprintf(stderr, "Error: ICMP packet too short\n");
      return;
  }

  /* Unused, and I don't think necessary. Get IP header */
  //sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

  /* Get ICMP header */
  sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

  /* Verify ICMP checksum */
  uint16_t received_cksum = icmp_hdr->icmp_sum;
  icmp_hdr->icmp_sum = 0;
  if (cksum(icmp_hdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t)) != received_cksum) {
      fprintf(stderr, "Error: Invalid ICMP checksum\n");
      return;
  }

  /* Check if it's an Echo Request (Type 8) */
  if (icmp_hdr->icmp_type == 8) {
      /* Send ICMP Echo Reply */
      send_icmp_message(sr, packet, len, 0, 0, interface);
  } else {
      /* Ignore other types of ICMP packets */
      fprintf(stderr, "Info: Ignoring non-Echo ICMP packet\n");
  }
}


void send_icmp_message(struct sr_instance *sr, 
  uint8_t *packet, 
  unsigned int len, 
  uint8_t type, 
  uint8_t code, 
  char *interface) {
/* Get original Ethernet and IP headers */
sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *)packet;
sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

/* Check minimum length for sending an ICMP message */
if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) {
fprintf(stderr, "Error: Packet too short for ICMP\n");
return;
}

/* Determine length of new ICMP packet */
unsigned int icmp_len;
if (type == 3 || type == 11) {
icmp_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
} else {
icmp_len = len; // Same length for Echo Reply
}

/* Allocate space for new ICMP packet */
uint8_t *icmp_packet = (uint8_t *)malloc(icmp_len);

/* Fill Ethernet header */
sr_ethernet_hdr_t *new_eth_hdr = (sr_ethernet_hdr_t *)icmp_packet;
memcpy(new_eth_hdr->ether_dhost, eth_hdr->ether_shost, ETHER_ADDR_LEN);

/* Get outgoing interface */
struct sr_if *out_iface = sr_get_interface(sr, interface);
memcpy(new_eth_hdr->ether_shost, out_iface->addr, ETHER_ADDR_LEN);
new_eth_hdr->ether_type = htons(ethertype_ip);

/* Fill IP header */
sr_ip_hdr_t *new_ip_hdr = (sr_ip_hdr_t *)(icmp_packet + sizeof(sr_ethernet_hdr_t));
new_ip_hdr->ip_v = 4;
new_ip_hdr->ip_hl = 5;
new_ip_hdr->ip_tos = 0;
new_ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + (type == 3 || type == 11 ? sizeof(sr_icmp_t3_hdr_t) : len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t)));
new_ip_hdr->ip_id = 0;
new_ip_hdr->ip_off = htons(IP_DF);
new_ip_hdr->ip_ttl = 64;
new_ip_hdr->ip_p = ip_protocol_icmp;
new_ip_hdr->ip_src = out_iface->ip;   // Router's IP
new_ip_hdr->ip_dst = ip_hdr->ip_src;  // Send ICMP back to sender

/* Recompute IP checksum */
new_ip_hdr->ip_sum = 0;
new_ip_hdr->ip_sum = cksum(new_ip_hdr, sizeof(sr_ip_hdr_t));

/* Create ICMP Header */
if (type == 3 || type == 11) {
/* Type 3 or Type 11: Use sr_icmp_t3_hdr */
sr_icmp_t3_hdr_t *icmp_t3_hdr = (sr_icmp_t3_hdr_t *)(icmp_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
icmp_t3_hdr->icmp_type = type;
icmp_t3_hdr->icmp_code = code;
icmp_t3_hdr->icmp_sum = 0;
icmp_t3_hdr->unused = 0;
icmp_t3_hdr->next_mtu = 0;

/* Copy original IP header + first 8 bytes of payload */
memcpy(icmp_t3_hdr->data, ip_hdr, ICMP_DATA_SIZE);

/* Compute ICMP checksum */
icmp_t3_hdr->icmp_sum = cksum(icmp_t3_hdr, sizeof(sr_icmp_t3_hdr_t));
} else if (type == 0) {
/* Type 0: Echo Reply */
sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(icmp_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
memcpy(icmp_hdr, packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));

icmp_hdr->icmp_type = 0;  // Echo Reply
icmp_hdr->icmp_code = 0;
icmp_hdr->icmp_sum = 0;
icmp_hdr->icmp_sum = cksum(icmp_hdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
}

/* Send the ICMP packet */
sr_send_packet(sr, icmp_packet, icmp_len, interface);

/* Free allocated memory */
free(icmp_packet);
}



struct sr_rt *longest_prefix_match(struct sr_instance *sr, uint32_t ip_dst) {
  struct sr_rt *rt_walker = sr->routing_table;
  struct sr_rt *best_match = NULL;
  uint32_t longest_mask = 0;

  /* Walk through the routing table */
  while (rt_walker) {
      /* Apply subnet mask to destination IP and routing entry destination */
      uint32_t masked_dst_ip = ip_dst & rt_walker->mask.s_addr;
      uint32_t masked_entry_ip = rt_walker->dest.s_addr & rt_walker->mask.s_addr;

      /* Check if the masked IPs match */
      if (masked_dst_ip == masked_entry_ip) {
          /* Check if this is the longest match so far */
          if (rt_walker->mask.s_addr > longest_mask) {
              best_match = rt_walker;
              longest_mask = rt_walker->mask.s_addr;
          }
      }
      /* Move to the next entry */
      rt_walker = rt_walker->next;
  }

  /* Return the best match or NULL if no match found */
  return best_match;
}
