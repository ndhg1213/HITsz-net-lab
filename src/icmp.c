#include "net.h"
#include "icmp.h"
#include "ip.h"

/**
 * @brief 发送icmp响应
 * 
 * @param req_buf 收到的icmp请求包
 * @param src_ip 源ip地址
 */
static void icmp_resp(buf_t *req_buf, uint8_t *src_ip)
{
    // TO-DO
    buf_t *buf = &txbuf;
    buf_init(buf, req_buf->len);
    memcpy(buf->data, req_buf->data, buf->len);
    icmp_hdr_t packet;
    icmp_hdr_t *icmp = (icmp_hdr_t *)req_buf->data;

    //填写ICMP报头
    packet.type = ICMP_TYPE_ECHO_REPLY;
    packet.code = 0;
    packet.id16 = icmp->id16;  //简单拷贝
    packet.seq16 = icmp->seq16;  //简单拷贝
    packet.checksum16 = swap16(0);  //先将校验和置0以计算校验和

    //更换ICMP报头计算整体校验和并发送
    memcpy(buf->data, &packet, sizeof(icmp_hdr_t));
    packet.checksum16 = swap16(checksum16((uint16_t *)buf->data, buf->len));
    memcpy(buf->data, &packet, sizeof(icmp_hdr_t));
    ip_out(buf, src_ip, NET_PROTOCOL_ICMP);
}

/**
 * @brief 处理一个收到的数据包
 * 
 * @param buf 要处理的数据包
 * @param src_ip 源ip地址
 */
void icmp_in(buf_t *buf, uint8_t *src_ip)
{
    // TO-DO
    //检查头部长度
    if(buf->len < sizeof(icmp_hdr_t)){
        return;
    }else{
        icmp_hdr_t *icmp = (icmp_hdr_t *)buf->data;

        //检查是否是回显报文
        if(icmp->type == ICMP_TYPE_ECHO_REQUEST && icmp->code == 0){
            icmp_resp(buf, src_ip);
        }else{
            return;
        }
    }
}

/**
 * @brief 发送icmp不可达
 * 
 * @param recv_buf 收到的ip数据包
 * @param src_ip 源ip地址
 * @param code icmp code，协议不可达或端口不可达
 */
void icmp_unreachable(buf_t *recv_buf, uint8_t *src_ip, icmp_code_t code)
{
    // TO-DO
    buf_t *buf = &txbuf;
    //初始化ICMP差错报文数据长度
    //复制源IP数据报头和前8个字节
    buf_init(buf, sizeof(ip_hdr_t) + 2 * NET_IP_LEN);
    memcpy(buf->data, recv_buf->data, sizeof(ip_hdr_t) + 2 * NET_IP_LEN);

    //填写ICMP报头
    icmp_hdr_t packet;
    packet.type = ICMP_TYPE_UNREACH;
    packet.code = code;
    packet.id16 = swap16(0);
    packet.seq16 = swap16(0);
    packet.checksum16 = swap16(0);  //先将校验和置0以计算校验和

    //更换ICMP报头计算整体校验和并发送
    buf_add_header(buf, sizeof(icmp_hdr_t));
    memcpy(buf->data, &packet, sizeof(icmp_hdr_t));
    packet.checksum16 = swap16(checksum16((uint16_t *)buf->data, buf->len));
    memcpy(buf->data, &packet, sizeof(icmp_hdr_t));
    ip_out(buf, src_ip, NET_PROTOCOL_ICMP);
}

/**
 * @brief 初始化icmp协议
 * 
 */
void icmp_init(){
    net_add_protocol(NET_PROTOCOL_ICMP, icmp_in);
}