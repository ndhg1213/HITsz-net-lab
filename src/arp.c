#include <string.h>
#include <stdio.h>
#include "net.h"
#include "arp.h"
#include "ethernet.h"
/**
 * @brief 初始的arp包
 * 
 */
static const arp_pkt_t arp_init_pkt = {
    .hw_type16 = constswap16(ARP_HW_ETHER),
    .pro_type16 = constswap16(NET_PROTOCOL_IP),
    .hw_len = NET_MAC_LEN,
    .pro_len = NET_IP_LEN,
    .sender_ip = NET_IF_IP,
    .sender_mac = NET_IF_MAC,
    .target_mac = {0}};

/**
 * @brief arp地址转换表，<ip,mac>的容器
 * 
 */
map_t arp_table;

/**
 * @brief arp buffer，<ip,buf_t>的容器
 * 
 */
map_t arp_buf;

/**
 * @brief 打印一条arp表项
 * 
 * @param ip 表项的ip地址
 * @param mac 表项的mac地址
 * @param timestamp 表项的更新时间
 */
void arp_entry_print(void *ip, void *mac, time_t *timestamp)
{
    printf("%s | %s | %s\n", iptos(ip), mactos(mac), timetos(*timestamp));
}

/**
 * @brief 打印整个arp表
 * 
 */
void arp_print()
{
    printf("===ARP TABLE BEGIN===\n");
    map_foreach(&arp_table, arp_entry_print);
    printf("===ARP TABLE  END ===\n");
}

/**
 * @brief 发送一个arp请求
 * 
 * @param target_ip 想要知道的目标的ip地址
 */
void arp_req(uint8_t *target_ip)
{
    // TO-DO
    buf_t *buf = &txbuf;
    buf_init(buf, sizeof(arp_pkt_t));  //初始化txbuf
    arp_pkt_t packet = arp_init_pkt;
    packet.opcode16 = swap16(ARP_REQUEST);  //填充opcode
    memcpy(packet.target_ip, target_ip, NET_IP_LEN);  //填充target_ip
    memcpy(buf->data, &packet, sizeof(arp_pkt_t));
    ethernet_out(buf, ether_broadcast_mac, NET_PROTOCOL_ARP);
}

/**
 * @brief 发送一个arp响应
 * 
 * @param target_ip 目标ip地址
 * @param target_mac 目标mac地址
 */
void arp_resp(uint8_t *target_ip, uint8_t *target_mac)
{
    // TO-DO
    buf_t *buf = &txbuf;
    buf_init(buf, sizeof(arp_pkt_t));  //初始化txbuf
    arp_pkt_t packet = arp_init_pkt;
    packet.opcode16 = swap16(ARP_REPLY);  //填充opcode
    memcpy(packet.target_ip, target_ip, NET_IP_LEN);  //填充target_ip
    memcpy(packet.target_mac, target_mac, NET_MAC_LEN);  //填充target_mac
    memcpy(buf->data, &packet, sizeof(arp_pkt_t));
    ethernet_out(buf, target_mac, NET_PROTOCOL_ARP); 
}

/**
 * @brief 处理一个收到的数据包
 * 
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void arp_in(buf_t *buf, uint8_t *src_mac)
{
    // TO-DO
    //数据包是否缺失
    if(buf->len < sizeof(arp_pkt_t)){
        return;
    }else{
        arp_pkt_t *arp = (arp_pkt_t *)buf->data;
        if(arp->hw_type16 != swap16(ARP_HW_ETHER) ||
            arp->hw_len != NET_MAC_LEN ||
            arp->pro_type16 != swap16(NET_PROTOCOL_IP) ||
            arp->pro_len != NET_IP_LEN ||
            (swap16(arp->opcode16) != ARP_REQUEST && swap16(arp->opcode16) != ARP_REPLY)){
                return;
            }else{
                map_set(&arp_table, arp->sender_ip, src_mac);
                buf_t *cache_buf = map_get(&arp_buf, arp->sender_ip);

                //cache_buf非空意味着当前接收方有需要发送数据包的目标
                //此时接收到的ARP数据包一定是ARP_REPLY
                //并且需要发送的目标即为该ARP数据包的发送方
                if(cache_buf != NULL){
                    ethernet_out(cache_buf, arp->sender_mac, NET_PROTOCOL_IP);
                    map_delete(&arp_buf, arp->sender_ip);

                //cache_buf为空意味着当前接收方没有需要发送数据包的目标
                //此时接收到的ARP数据包一定是ARP_REQUEST
                //需要向该ARP数据包的发送方发送ARP_REPLY
                }else{
                    if(swap16(arp->opcode16) == ARP_REQUEST && !memcmp(arp->target_ip, net_if_ip, NET_IP_LEN)){
                        arp_resp(arp->sender_ip, arp->sender_mac);
                    }
                }
            }
    }
}

/**
 * @brief 处理一个要发送的数据包
 * 
 * @param buf 要处理的数据包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void arp_out(buf_t *buf, uint8_t *ip)
{
    // TO-DO
    uint8_t *target_mac = map_get(&arp_table, ip);
    if(target_mac == NULL){
        buf_t *cache_buf = map_get(&arp_buf, ip);
        if(cache_buf != NULL){
            return;
        }else{
            //设置目标ip的map缓存
            map_set(&arp_buf, ip, buf);
            arp_req(ip);
        }
    }else{
        ethernet_out(buf, target_mac, NET_PROTOCOL_IP);
    }
}

/**
 * @brief 初始化arp协议
 * 
 */
void arp_init()
{
    map_init(&arp_table, NET_IP_LEN, NET_MAC_LEN, 0, ARP_TIMEOUT_SEC, NULL);
    map_init(&arp_buf, NET_IP_LEN, sizeof(buf_t), 0, ARP_MIN_INTERVAL, buf_copy);
    net_add_protocol(NET_PROTOCOL_ARP, arp_in);
    arp_req(net_if_ip);
}