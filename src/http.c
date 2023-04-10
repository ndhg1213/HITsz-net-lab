#include "http.h"
#include "tcp.h"
#include "net.h"
#include "assert.h"

#define TCP_FIFO_SIZE 40

typedef struct http_fifo {
    tcp_connect_t* buffer[TCP_FIFO_SIZE];
    uint8_t front, tail, count;
} http_fifo_t;

static http_fifo_t http_fifo_v;

static void http_fifo_init(http_fifo_t* fifo) {
    fifo->count = 0;
    fifo->front = 0;
    fifo->tail = 0;
}

static int http_fifo_in(http_fifo_t* fifo, tcp_connect_t* tcp) {
    if (fifo->count >= TCP_FIFO_SIZE) {
        return -1;
    }
    fifo->buffer[fifo->front] = tcp;
    fifo->front++;
    if (fifo->front >= TCP_FIFO_SIZE) {
        fifo->front = 0;
    }
    fifo->count++;
    return 0;
}

static tcp_connect_t* http_fifo_out(http_fifo_t* fifo) {
    if (fifo->count == 0) {
        return NULL;
    }
    tcp_connect_t* tcp = fifo->buffer[fifo->tail];
    fifo->tail++;
    if (fifo->tail >= TCP_FIFO_SIZE) {
        fifo->tail = 0;
    }
    fifo->count--;
    return tcp;
}

static size_t get_line(tcp_connect_t* tcp, char* buf, size_t size) {
    size_t i = 0;
    while (i < size) {
        char c;
        if (tcp_connect_read(tcp, (uint8_t*)&c, 1) > 0) {
            if (c == '\n') {
                break;
            }
            if (c != '\n' && c != '\r') {
                buf[i] = c;
                i++;
            }
        }
        net_poll();
    }
    buf[i] = '\0';
    return i;
}

static size_t http_send(tcp_connect_t* tcp, const char* buf, size_t size) {
    size_t send = 0;
    while (send < size) {
        send += tcp_connect_write(tcp, (const uint8_t*)buf + send, size - send);
        net_poll();
    }
    return send;
}

static void close_http(tcp_connect_t* tcp) {
    tcp_connect_close(tcp);
    printf("http closed.\n");
}



static void send_file(tcp_connect_t* tcp, const char* url) {
    FILE* file;
    char file_path[255];
    char tx_buffer[1024];

    //解析url路径
    memcpy(file_path, XHTTP_DOC_DIR, sizeof(XHTTP_DOC_DIR));

    //如果只有/则默认为index.html
    if(strlen(url) == 1){
        strcat(file_path, "/index.html");
    }else{
        strcat(file_path, url);
    }
    file = fopen(file_path, "rb");  //二进制方法打开文件

    //文件不存在发送404
    if(file == NULL){

        //填充http报头
        sprintf(tx_buffer, "HTTP/1.0 404 NOT FOUND\r\n");
        http_send(tcp, tx_buffer, strlen(tx_buffer));
        sprintf(tx_buffer, "Sever: \r\n");  //提供服务者缺省
        http_send(tcp, tx_buffer, strlen(tx_buffer));
        sprintf(tx_buffer, "Content-Type: text/html\r\n");
        http_send(tcp, tx_buffer, strlen(tx_buffer));
        sprintf(tx_buffer, "\r\n");
        http_send(tcp, tx_buffer, strlen(tx_buffer));
        sprintf(tx_buffer, "<HTML><TITLE>Not Found</TITLE>\r\n");
        http_send(tcp, tx_buffer, strlen(tx_buffer));
        sprintf(tx_buffer, "The resource specified\r\n");
        http_send(tcp, tx_buffer, strlen(tx_buffer));
        sprintf(tx_buffer, "is unavailable or nonexistent.\r\n");
        http_send(tcp, tx_buffer, strlen(tx_buffer));
        sprintf(tx_buffer, "</BODY></HTML>\r\n");
        http_send(tcp, tx_buffer, strlen(tx_buffer));
    }
    
    //资源存在
    else{
        sprintf(tx_buffer, "HTTP/1.0 200 OK\r\n");
        http_send(tcp, tx_buffer, strlen(tx_buffer));
        sprintf(tx_buffer, "Sever: \r\n");  //提供服务者缺省
        http_send(tcp, tx_buffer, strlen(tx_buffer));
        sprintf(tx_buffer, "Content-Type: \r\n");  //由于需要传输text与jpg直接缺省
        http_send(tcp, tx_buffer, strlen(tx_buffer));
        sprintf(tx_buffer, "\r\n");
        http_send(tcp, tx_buffer, strlen(tx_buffer));

        //读取html以及jpg文件
        memset(tx_buffer, 0, sizeof(tx_buffer));
        while(fread(tx_buffer, sizeof(char), sizeof(tx_buffer), file) > 0){
            http_send(tcp, tx_buffer, sizeof(tx_buffer));
            memset(tx_buffer, 0, sizeof(tx_buffer));
        }
        fclose(file);
    }

}

static void http_handler(tcp_connect_t* tcp, connect_state_t state) {
    if (state == TCP_CONN_CONNECTED) {
        http_fifo_in(&http_fifo_v, tcp);
        printf("http conntected.\n");
    } else if (state == TCP_CONN_DATA_RECV) {
    } else if (state == TCP_CONN_CLOSED) {
        printf("http closed.\n");
    } else {
        assert(0);
    }
}


// 在端口上创建服务器。
int http_server_open(uint16_t port) {
    if (!tcp_open(port, http_handler)) {
        return -1;
    }
    http_fifo_init(&http_fifo_v);
    return 0;
}

// 从FIFO取出请求并处理。新的HTTP请求时会发送到FIFO中等待处理。
void http_server_run(void) {
    tcp_connect_t* tcp;
    char url_path[255];
    char rx_buffer[1024];

    while ((tcp = http_fifo_out(&http_fifo_v)) != NULL) {
        int i;
        char* c = rx_buffer;

        //调用get_line获取请求报文的方法
        size_t size = get_line(tcp, c, 1023);
        if(size == 0){
            close_http(tcp);
            continue;
        }

        //判断是否是GET请求
        char method[4];
        memcpy(method, c, 3);
        if(strcmp(method, "GET")){
            close_http(tcp);
            continue;
        }

        //解析路径
        i = 0;
        int j = 0;
        while(c[i] != ' '){
            i++;
        }
        i++; //跳过空格
        while(c[i] != ' '){
            url_path[j] = c[i];
            j++;
            i++;
        }
        url_path[j] = '\0';

        send_file(tcp, url_path);

        //一次http传输结束关闭tcp链接
        close_http(tcp);


        printf("!! final close\n");
    }
}
