#include "udp.h"
#include "ip.h"
#include "icmp.h"

/**
 * @brief udp处理程序表
 * 
 */
map_t udp_table;

/**
 * @brief udp伪校验和计算
 * 
 * @param buf 要计算的包
 * @param src_ip 源ip地址
 * @param dst_ip 目的ip地址
 * @return uint16_t 伪校验和
 */
static uint16_t udp_checksum(buf_t *buf, uint8_t *src_ip, uint8_t *dst_ip)
{
    // TO-DO
    uint16_t checksum = 0;
    udp_peso_hdr_t packet;
    ip_hdr_t ip;

    //暂存IP报头
    buf_add_header(buf, sizeof(ip_hdr_t));
    memcpy(&ip, buf->data, sizeof(ip_hdr_t));
    buf_remove_header(buf, sizeof(ip_hdr_t));

    //填充伪UDP报头
    packet.total_len16 = swap16(buf->len);
    packet.placeholder = 0;
    packet.protocol = NET_PROTOCOL_UDP;
    memcpy(packet.dst_ip, dst_ip, NET_IP_LEN);
    memcpy(packet.src_ip, src_ip, NET_IP_LEN);

    //添加UDP伪报头计算整体校验和
    buf_add_header(buf, sizeof(udp_peso_hdr_t));
    memcpy(buf->data, &packet, sizeof(udp_peso_hdr_t));
    checksum = checksum16((uint16_t *)buf->data, buf->len);

    //拷贝IP报头
    buf_remove_header(buf, sizeof(udp_peso_hdr_t));
    buf_add_header(buf, sizeof(ip_hdr_t));
    memcpy(buf->data, &ip, sizeof(ip_hdr_t));
    buf_remove_header(buf, sizeof(ip_hdr_t));
    return checksum;
}
/**
 * @brief 处理一个收到的udp数据包
 * 
 * @param buf 要处理的包
 * @param src_ip 源ip地址
 */
void udp_in(buf_t *buf, uint8_t *src_ip)
{
    // TO-DO
    //数据包是否缺失
    if(buf->len < sizeof(udp_hdr_t)){
        return;
    }else{

        //判断校验和是否正确
        udp_hdr_t *udp = (udp_hdr_t *)buf->data;
        uint16_t hdr_checksum = swap16(udp->checksum16);
        udp->checksum16 = swap16(0);
        if(hdr_checksum != udp_checksum(buf, src_ip, net_if_ip)){
            return;
        }else{
            udp->checksum16 = swap16(hdr_checksum);  //恢复校验和值

            //查询回调函数
            uint16_t port = swap16(udp->dst_port16);
            udp_handler_t *handler = map_get(&udp_table, &port);
            if(handler == NULL){

                //直接调用buf_add_header将隐藏的IP数据报头取回即可
                buf_add_header(buf, sizeof(ip_hdr_t));
                icmp_unreachable(buf, net_if_ip, ICMP_CODE_PORT_UNREACH);
            }else{
                buf_remove_header(buf, sizeof(udp_hdr_t));
                (*handler)(buf->data, buf->len, src_ip, port);
            }
        }
    }
}

/**
 * @brief 处理一个要发送的数据包
 * 
 * @param buf 要处理的包
 * @param src_port 源端口号
 * @param dst_ip 目的ip地址
 * @param dst_port 目的端口号
 */
void udp_out(buf_t *buf, uint16_t src_port, uint8_t *dst_ip, uint16_t dst_port)
{
    // TO-DO
    udp_hdr_t packet;

    //填充UDP报头
    packet.src_port16 = swap16(src_port);
    packet.dst_port16 = swap16(dst_port);
    packet.total_len16 = swap16(buf->len + sizeof(udp_hdr_t));
    packet.checksum16 = swap16(0);  //先将校验和置0以计算校验和

    //添加UDP报头计算整体校验和并发送
    buf_add_header(buf, sizeof(udp_hdr_t));
    memcpy(buf->data, &packet, sizeof(udp_hdr_t));
    packet.checksum16 = swap16(udp_checksum(buf, net_if_ip, dst_ip));
    memcpy(buf->data, &packet, sizeof(udp_hdr_t));
    ip_out(buf, dst_ip, NET_PROTOCOL_UDP);
}

/**
 * @brief 初始化udp协议
 * 
 */
void udp_init()
{
    map_init(&udp_table, sizeof(uint16_t), sizeof(udp_handler_t), 0, 0, NULL);
    net_add_protocol(NET_PROTOCOL_UDP, udp_in);
}

/**
 * @brief 打开一个udp端口并注册处理程序
 * 
 * @param port 端口号
 * @param handler 处理程序
 * @return int 成功为0，失败为-1
 */
int udp_open(uint16_t port, udp_handler_t handler)
{
    return map_set(&udp_table, &port, &handler);
}

/**
 * @brief 关闭一个udp端口
 * 
 * @param port 端口号
 */
void udp_close(uint16_t port)
{
    map_delete(&udp_table, &port);
}

/**
 * @brief 发送一个udp包
 * 
 * @param data 要发送的数据
 * @param len 数据长度
 * @param src_port 源端口号
 * @param dst_ip 目的ip地址
 * @param dst_port 目的端口号
 */
void udp_send(uint8_t *data, uint16_t len, uint16_t src_port, uint8_t *dst_ip, uint16_t dst_port)
{
    buf_init(&txbuf, len);
    memcpy(txbuf.data, data, len);
    udp_out(&txbuf, src_port, dst_ip, dst_port);
}