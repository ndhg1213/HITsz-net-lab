#include "net.h"
#include "ip.h"
#include "ethernet.h"
#include "arp.h"
#include "icmp.h"

/**
 * @brief 处理一个收到的数据包
 * 
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void ip_in(buf_t *buf, uint8_t *src_mac)
{
    // TO-DO
    //数据包是否缺失
    if(buf->len < sizeof(ip_hdr_t)){
        return;
    }else{
        ip_hdr_t *ip = (ip_hdr_t *)buf->data;

        //判断版本号以及总长度字段是否合法
        if(ip->version != IP_VERSION_4 ||
            swap16(ip->total_len16) > buf->len){
                return;
            }else{

                //判断校验和是否正确
                uint16_t hdr_checksum = swap16(ip->hdr_checksum16);
                ip->hdr_checksum16 = swap16(0);
                if(hdr_checksum != checksum16((uint16_t *)ip, sizeof(ip_hdr_t))){
                    return;
                }else{
                    ip->hdr_checksum16 = swap16(hdr_checksum);  //恢复校验和值

                    //对比目的ip地址与本机ip地址
                    if(memcmp(ip->dst_ip, net_if_ip, NET_IP_LEN)){
                        return;
                    }else{

                        //判断是否存在填充字段并去除
                        if(buf->len > swap16(ip->total_len16)){
                            buf_remove_padding(buf, buf->len - swap16(ip->total_len16));
                        }

                        //判断协议是否合法
                        if(ip->protocol == NET_PROTOCOL_ICMP ||
                            ip->protocol == NET_PROTOCOL_TCP ||  //该实验框架不兼容TCP
                            ip->protocol == NET_PROTOCOL_UDP){
                                buf_remove_header(buf, sizeof(ip_hdr_t));
                                net_in(buf, ip->protocol, ip->src_ip);
                            }else{
                                icmp_unreachable(buf, ip->src_ip, ICMP_CODE_PROTOCOL_UNREACH);
                            }
                    }
                }
            }
    }
}

/**
 * @brief 处理一个要发送的ip分片
 * 
 * @param buf 要发送的分片
 * @param ip 目标ip地址
 * @param protocol 上层协议
 * @param id 数据包id
 * @param offset 分片offset，必须被8整除
 * @param mf 分片mf标志，是否有下一个分片
 */
void ip_fragment_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol, int id, uint16_t offset, int mf)
{
    // TO-DO
    ip_hdr_t packet;

    //填写ip数据报头
    packet.hdr_len = 5;
    packet.version = IP_VERSION_4;
    packet.tos = 0;
    packet.total_len16 = swap16(buf->len + sizeof(ip_hdr_t));
    packet.id16 = swap16(id);
    if(mf){
        packet.flags_fragment16 = swap16(0x2000 | offset);  //当存在下一分片时，标志位为001
    }else{
        packet.flags_fragment16 = swap16(offset);  //不存在下一分片时，标志位为000
    }
    packet.protocol = protocol;
    packet.ttl = IP_DEFALUT_TTL;
    packet.hdr_checksum16 = swap16(0);  //先将校验和置0以运算校验和
    memcpy(packet.dst_ip, ip, NET_IP_LEN);
    memcpy(packet.src_ip, net_if_ip, NET_IP_LEN);
    packet.hdr_checksum16 = swap16(checksum16((uint16_t *)(&packet), sizeof(ip_hdr_t)));
    buf_add_header(buf, sizeof(ip_hdr_t));
    memcpy(buf->data, &packet, sizeof(ip_hdr_t));
    arp_out(buf, ip);
}

/**
 * @brief 处理一个要发送的ip数据包
 * 
 * @param buf 要处理的包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void ip_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol)
{
    // TO-DO
    static uint16_t ip_id = 0;

    //数据长度小于1480直接发送
    if(buf->len <= ETHERNET_MAX_TRANSPORT_UNIT - sizeof(ip_hdr_t)){
        ip_fragment_out(buf, ip, protocol, ip_id, 0, 0);
        ip_id += 1;
    }else{

        //奇怪的bug：必须将ip_buf定义为buf_t，如果定义成buf_t *会出现segfault
        //也不能简单的将ip_buf设置为rxbuf或txbuf，会导致卡死
        buf_t ip_buf;
        uint16_t len_sum = 0;

        //每次分割1480长度的切片
        while(buf->len > ETHERNET_MAX_TRANSPORT_UNIT - sizeof(ip_hdr_t)){
            buf_init(&ip_buf, ETHERNET_MAX_TRANSPORT_UNIT - sizeof(ip_hdr_t));
            memcpy(ip_buf.data, buf->data, ETHERNET_MAX_TRANSPORT_UNIT - sizeof(ip_hdr_t));
            ip_fragment_out(&ip_buf, ip, protocol, ip_id, len_sum/IP_HDR_OFFSET_PER_BYTE, 1);
            buf_remove_header(buf, ETHERNET_MAX_TRANSPORT_UNIT - sizeof(ip_hdr_t));
            len_sum += ETHERNET_MAX_TRANSPORT_UNIT - sizeof(ip_hdr_t);
        }
        
        //发送最后一个切片
        if(buf->len != 0){
            buf_init(&ip_buf, buf->len);
            memcpy(ip_buf.data, buf->data, buf->len);
            ip_fragment_out(&ip_buf, ip, protocol, ip_id, len_sum/IP_HDR_OFFSET_PER_BYTE, 0);
            ip_id += 1;
        }
    }
}

/**
 * @brief 初始化ip协议
 * 
 */
void ip_init()
{
    net_add_protocol(NET_PROTOCOL_IP, ip_in);
}