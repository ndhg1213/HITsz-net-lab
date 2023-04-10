#include <assert.h>
#include "map.h"
#include "tcp.h"
#include "ip.h"

static void panic(const char* msg, int line) {
    printf("panic %s! at line %d\n", msg, line);
    assert(0);
}

static void display_flags(tcp_flags_t flags) {
    printf("flags:%s%s%s%s%s%s%s%s\n",
        flags.cwr ? " cwr" : "",
        flags.ece ? " ece" : "",
        flags.urg ? " urg" : "",
        flags.ack ? " ack" : "",
        flags.psh ? " psh" : "",
        flags.rst ? " rst" : "",
        flags.syn ? " syn" : "",
        flags.fin ? " fin" : ""
    );
}

// dst-port -> handler
static map_t tcp_table; //tcp_table里面放了一个dst_port的回调函数

// tcp_key_t[IP, src port, dst port] -> tcp_connect_t

/* Connect_table放置了一堆TCP连接，
    KEY为[IP，src port，dst port], 即tcp_key_t，VALUE为tcp_connect_t。
*/
static map_t connect_table; 

/**
 * @brief 生成一个用于 connect_table 的 key
 *
 * @param ip
 * @param src_port
 * @param dst_port
 * @return tcp_key_t
 */
static tcp_key_t new_tcp_key(uint8_t ip[NET_IP_LEN], uint16_t src_port, uint16_t dst_port) {
    tcp_key_t key;
    memcpy(key.ip, ip, NET_IP_LEN);
    key.src_port = src_port;
    key.dst_port = dst_port;
    return key;
}

/**
 * @brief 初始化tcp在静态区的map
 *        供应用层使用
 *
 */
void tcp_init() {
    map_init(&tcp_table, sizeof(uint16_t), sizeof(tcp_handler_t), 0, 0, NULL);
    map_init(&connect_table, sizeof(tcp_key_t), sizeof(tcp_connect_t), 0, 0, NULL);
    net_add_protocol(NET_PROTOCOL_TCP, tcp_in);
}

/**
 * @brief 向 port 注册一个 TCP 连接以及关联的回调函数
 *        供应用层使用
 *
 * @param port
 * @param handler
 * @return int
 */
int tcp_open(uint16_t port, tcp_handler_t handler) {
    printf("tcp open\n");
    return map_set(&tcp_table, &port, &handler);
}

/**
 * @brief 完成了缓存分配工作，状态也会切换为TCP_SYN_RCVD
 *        rx_buf和tx_buf在触及边界时会把数据重新移动到头部，防止溢出。
 *
 * @param connect
 */
static void init_tcp_connect_rcvd(tcp_connect_t* connect) {
    if (connect->state == TCP_LISTEN) {
        connect->rx_buf = malloc(sizeof(buf_t));
        connect->tx_buf = malloc(sizeof(buf_t));
    }
    buf_init(connect->rx_buf, 0);
    buf_init(connect->tx_buf, 0);
    connect->state = TCP_SYN_RCVD;
}

/**
 * @brief 释放TCP连接，这会释放分配的空间，并把状态变回LISTEN。
 *        一般这个后边都会跟个map_delete(&connect_table, &key)把状态变回CLOSED
 *
 * @param connect
 */
static void release_tcp_connect(tcp_connect_t* connect) {
    if (connect->state == TCP_LISTEN)
        return;
    free(connect->rx_buf);
    free(connect->tx_buf);
    connect->state = TCP_LISTEN;
}

static uint16_t tcp_checksum(buf_t* buf, uint8_t* src_ip, uint8_t* dst_ip) {
    uint16_t len = (uint16_t)buf->len;
    tcp_peso_hdr_t* peso_hdr = (tcp_peso_hdr_t*)(buf->data - sizeof(tcp_peso_hdr_t));
    tcp_peso_hdr_t pre; //暂存被覆盖的IP头
    memcpy(&pre, peso_hdr, sizeof(tcp_peso_hdr_t));
    memcpy(peso_hdr->src_ip, src_ip, NET_IP_LEN);
    memcpy(peso_hdr->dst_ip, dst_ip, NET_IP_LEN);
    peso_hdr->placeholder = 0;
    peso_hdr->protocol = NET_PROTOCOL_TCP;
    peso_hdr->total_len16 = swap16(len);
    uint16_t checksum = checksum16((uint16_t*)peso_hdr, len + sizeof(tcp_peso_hdr_t));
    memcpy(peso_hdr, &pre, sizeof(tcp_peso_hdr_t));
    return checksum;
}

static _Thread_local uint16_t delete_port;

/**
 * @brief tcp_close使用这个函数来查找可以关闭的连接，使用thread-local变量delete_port传递端口号。
 *
 * @param key,value,timestamp
 */
static void close_port_fn(void* key, void* value, time_t* timestamp) {
    tcp_key_t* tcp_key = key;
    tcp_connect_t* connect = value;
    if (tcp_key->dst_port == delete_port) {
        release_tcp_connect(connect);
    }
}

/**
 * @brief 关闭 port 上的 TCP 连接
 *        供应用层使用
 *
 * @param port
 */
void tcp_close(uint16_t port) {
    delete_port = port;
    map_foreach(&connect_table, close_port_fn);
    map_delete(&tcp_table, &port);
}

/**
 * @brief 从 buf 中读取数据到 connect->rx_buf
 *
 * @param connect
 * @param buf
 * @return uint16_t 字节数
 */
static uint16_t tcp_read_from_buf(tcp_connect_t* connect, buf_t* buf) {
    uint8_t* dst = connect->rx_buf->data + connect->rx_buf->len;
    buf_add_padding(connect->rx_buf, buf->len);
    memcpy(dst, buf->data, buf->len);
    connect->ack += buf->len;
    return buf->len;
}

/**
 * @brief 把connect内tx_buf的数据写入到buf里面供tcp_send使用，buf原来的内容会无效。
 *
 * @param connect
 * @param buf
 * @return uint16_t 字节数
 */
static uint16_t tcp_write_to_buf(tcp_connect_t* connect, buf_t* buf) {
    uint16_t sent = connect->next_seq - connect->unack_seq;
    uint16_t size = min32(connect->tx_buf->len - sent, connect->remote_win);
    buf_init(buf, size);
    memcpy(buf->data, connect->tx_buf->data + sent, size);
    connect->next_seq += size;
    return size;
}

/**
 * @brief 发送TCP包, seq_number32 = connect->next_seq - buf->len
 *        buf里的数据将作为负载，加上tcp头发送出去。如果flags包含syn或fin，seq会递增。
 *
 * @param buf
 * @param connect
 * @param flags
 */
static void tcp_send(buf_t* buf, tcp_connect_t* connect, tcp_flags_t flags) {
    // printf("<< tcp send >> sz=%zu\n", buf->len);
    display_flags(flags);
    size_t prev_len = buf->len;
    buf_add_header(buf, sizeof(tcp_hdr_t));
    tcp_hdr_t* hdr = (tcp_hdr_t*)buf->data;
    hdr->src_port16 = swap16(connect->local_port);
    hdr->dst_port16 = swap16(connect->remote_port);
    hdr->seq_number32 = swap32(connect->next_seq - prev_len);
    hdr->ack_number32 = swap32(connect->ack);
    hdr->data_offset = sizeof(tcp_hdr_t) / sizeof(uint32_t);
    hdr->reserved = 0;
    hdr->flags = flags;
    hdr->window_size16 = swap16(connect->remote_win);
    hdr->chunksum16 = 0;
    hdr->urgent_pointer16 = 0;
    hdr->chunksum16 = swap16(tcp_checksum(buf, connect->ip, net_if_ip));  //大小端转换
    ip_out(buf, connect->ip, NET_PROTOCOL_TCP);
    if (flags.syn || flags.fin) {
        connect->next_seq += 1;
    }
}

/**
 * @brief 从外部关闭一个TCP连接, 会发送剩余数据
 *        供应用层使用
 *
 * @param connect
 */
void tcp_connect_close(tcp_connect_t* connect) {
    if (connect->state == TCP_ESTABLISHED) {
        tcp_write_to_buf(connect, &txbuf);
        tcp_send(&txbuf, connect, tcp_flags_ack_fin);
        connect->state = TCP_FIN_WAIT_1;
        return;
    }
    tcp_key_t key = new_tcp_key(connect->ip, connect->remote_port, connect->local_port);
    release_tcp_connect(connect);
    map_delete(&connect_table, &key);
}

/**
 * @brief 从 connect 中读取数据到 buf，返回成功的字节数。
 *        供应用层使用
 *
 * @param connect
 * @param data
 * @param len
 * @return size_t
 */
size_t tcp_connect_read(tcp_connect_t* connect, uint8_t* data, size_t len) {
    buf_t* rx_buf = connect->rx_buf;
    size_t size = min32(rx_buf->len, len);
    memcpy(data, rx_buf->data, size);
    if (buf_remove_header(rx_buf, size) != 0) {
        memmove(rx_buf->payload, rx_buf->data, rx_buf->len);
        rx_buf->data = rx_buf->payload;
    }
    return size;
}

/**
 * @brief 往connect的tx_buf里面写东西，返回成功的字节数，这里要判断窗口够不够，否则图片显示不全。
 *        供应用层使用
 *
 * @param connect
 * @param data
 * @param len
 */
size_t tcp_connect_write(tcp_connect_t* connect, const uint8_t* data, size_t len) {
    // printf("tcp_connect_write size: %zu\n", len);
    buf_t* tx_buf = connect->tx_buf;

    uint8_t* dst = tx_buf->data + tx_buf->len;
    size_t size = min32(&tx_buf->payload[BUF_MAX_LEN] - dst, len);

    if (connect->next_seq - connect->unack_seq + len >= connect->remote_win) {
        return 0;
    }
    if (buf_add_padding(tx_buf, size) != 0) {
        memmove(tx_buf->payload, tx_buf->data, tx_buf->len);
        tx_buf->data = tx_buf->payload;
        if (tcp_write_to_buf(connect, &txbuf)) {
            tcp_send(&txbuf, connect, tcp_flags_ack);
        }
        return 0;
    }
    memcpy(dst, data, size);
    return size;
}

/**
 * @brief 服务器端TCP收包
 *
 * @param buf
 * @param src_ip
 */
void tcp_in(buf_t* buf, uint8_t* src_ip) {

    //数据包缺失
    if(buf->len < sizeof(tcp_hdr_t)){
        return;
    }

    //检查校验和值
    tcp_hdr_t *tcp = (tcp_hdr_t *)buf->data;
    uint16_t checksum = swap16(tcp->chunksum16);
    tcp->chunksum16 = swap16(0);  //将校验和置0
    if(checksum != tcp_checksum(buf, src_ip, net_if_ip)){
        return;
    }
    tcp->chunksum16 = swap16(checksum);  //恢复校验和值

    //从tcp头部字段中获取src_port、dst_port、window、seq_number、ack_number、flags
    uint16_t src_port = swap16(tcp->src_port16);
    uint16_t dst_port = swap16(tcp->dst_port16);
    uint16_t window = swap16(tcp->window_size16);
    uint32_t seq_number = swap32(tcp->seq_number32);
    uint32_t ack_number = swap32(tcp->ack_number32);
    tcp_flags_t flags = tcp->flags;

    //查询回调函数
    tcp_handler_t *handler = map_get(&tcp_table, &dst_port);
    if(handler == NULL){
        return;
    }

    //查询链接
    tcp_key_t key = new_tcp_key(src_ip, src_port, dst_port);
    tcp_connect_t *connect = map_get(&connect_table, &key);

    //链接不存在时创建一个新链接并将其状态设置为TCP_LISTEN
    if(connect == NULL){
        connect = (tcp_connect_t *)malloc(sizeof(tcp_connect_t));
        connect->state = TCP_LISTEN;
        map_set(&connect_table, &key, connect);
    }
    connect = map_get(&connect_table, &key);

    //TCP_LISTEN状态
    if(connect->state == TCP_LISTEN){

        //服务端收到的第一个包rst有效
        //服务端直接断开连接
        if(flags.rst == 1){
            tcp_connect_close(connect);
        }

        //服务端收到的第一个包必须是第一次握手即syn有效
        else if(flags.syn == 0){
            printf("!!! reset tcp !!!\n");
            connect->next_seq = 0;
            connect->ack = seq_number + 1;
            buf_init(&txbuf, 0);
            tcp_send(&txbuf, connect, tcp_flags_ack_rst);
        }else{
            init_tcp_connect_rcvd(connect);
            connect->local_port = dst_port;  //本地端口
            connect->remote_port = src_port;  //远程端口
            memcpy(connect->ip, src_ip, NET_IP_LEN);

            srand(time(NULL));
            connect->unack_seq = rand()%(UINT16_MAX);  //选取随机数作为服务端的seq
            connect->next_seq = connect->unack_seq;
            connect->ack = seq_number + 1;
            connect->remote_win = window;
            buf_init(&txbuf, 0);
            tcp_send(&txbuf, connect, tcp_flags_ack_syn);  //第二次握手
        }
        return;
    }

    //检查接收到的seq_number
    //如果与ack序号不一致则发送ack_syn复位链接
    if(seq_number != connect->ack){
        printf("!!! reset tcp !!!\n");
        buf_init(&txbuf, 0);
        tcp_send(&txbuf, connect, tcp_flags_ack_syn);
        return;
    }

    //检查rst是否有效
    //如果有则重置链接
    if(flags.rst == 1){
        tcp_connect_close(connect);
        return;
    }

    //序号相同时调用buf_remove_header去除TCP报头
    buf_remove_header(buf, sizeof(tcp_hdr_t));

    //进行状态转换
    switch (connect->state) {

    //此时已经完成至少两次握手不应该出现TCP_LISTEN状态
    case TCP_LISTEN:
        panic("switch TCP_LISTEN", __LINE__);
        break;

    //等待第三次握手
    case TCP_SYN_RCVD:

        //没有收到第三次握手继续等待
        if(flags.ack == 0){
            break;
        }

        //收到第三次握手
        connect->unack_seq += 1;  //由于第二次握手需要消耗一个seq因此将unack + 1与next_seq同步
        connect->state = TCP_ESTABLISHED;  //完成三次握手状态转换为ESTABLISHED
        (*handler)(connect, TCP_CONN_CONNECTED); 
        break;

    case TCP_ESTABLISHED:

        //没有收到ack或是fin
        if(flags.ack == 0 && flags.fin == 0){
            break;
        }

        //ack有效
        if(flags.ack == 1){

            //判断收到的ack_number是否是在已发送但未确认的窗口内
            //根据累计确认推进unack_seq并删去选择重传的数据
            if(connect->unack_seq < ack_number && connect->next_seq > ack_number){
                buf_remove_header(connect->tx_buf, ack_number - connect->unack_seq);
                connect->unack_seq = ack_number;
            }
        }

        //调用tcp_read_from_buf函数，把buf放入rx_buf中
        tcp_read_from_buf(connect, buf);
        buf_init(&txbuf, 0);  //初始化txbuf

        //fin有效服务端将二次挥手与三次挥手合并跳过CLOSE_WAIT状态
        if(flags.fin == 1){
            connect->state = TCP_LAST_ACK;
            connect->ack += 1;
            tcp_send(&txbuf, connect, tcp_flags_ack_fin);
        }
        
        //只收到了ack有效保持ESTABLISHED状态
        else{
            if(buf->len != 0){
                (*handler)(connect, TCP_CONN_DATA_RECV);
                tcp_write_to_buf(connect, &txbuf);  //将要发送的数据写入txbuf
                tcp_send(&txbuf, connect, tcp_flags_ack);  //将数据和ack合并发送
            }
        }
        break;

    case TCP_CLOSE_WAIT:
        panic("switch TCP_CLOSE_WAIT", __LINE__);
        break;

    case TCP_FIN_WAIT_1:

        //如果收到fin&&ack有效即第三次挥手则直接关闭链接
        if(flags.fin == 1 && flags.ack == 1){
            tcp_connect_close(connect);
        }

        //如果只收到了ack有效即第二次挥手需要等待客户端传输数据
        if(flags.fin == 0 && flags.ack == 1){
            connect->state = TCP_FIN_WAIT_2;
        }
        break;

    case TCP_FIN_WAIT_2:

        //收到fin有效即第三次挥手
        if(flags.fin == 1){
            connect->ack += 1;  //将ack + 1
            buf_init(&txbuf, 0);
            tcp_send(&txbuf, connect, tcp_flags_ack);  //调用tcp_send发送一个ack数据包
            tcp_connect_close(connect);  //关闭tcp链接
        }
        break;

    case TCP_LAST_ACK:

        //收到ack有效即第四次挥手
        if(flags.ack == 1){
            (*handler)(connect, TCP_CONN_CLOSED);
            tcp_connect_close(connect);  //关闭tcp链接
        }
        break;

    default:
        panic("connect->state", __LINE__);
        break;
    }
    return;
}
