---
published: true
categories: [AFL]
---
## 利用AFL Fuzz Server

Lolware在4月份写了一篇文章关于如何利用[AFL fuzz Nginx](https://lolware.net/2015/04/28/nginx-fuzzing.html)。AFL本身针对处理文件类型的程序进行Fuzz，而针对处理网络协议类型的程序并不能很好的支持。在博客中Lolware说其借助preeny中的desock将socket重定向到stdin/stdout以解决AFL对网络协议类型程序不能处理的问题。但是根据blog中的内容我进行了反复实验却没能成功，主要问题发生在重定向之后nginx处理请求时延迟过长导致不能正常进行测试，并且对于WebServer这种服务程序在处理请求时需要考虑到大量关键字问题，也就是说如果在afl中添加预设字典效果会更好一些。

时间到了7月，Jonathan Foote写了一篇[How to fuzz a server with American Fuzzy  Lop](https://www.fastly.com/blog/how-to-fuzz-server-american-fuzzy-lop)，其中用到了AFL的Persistent mode和select的方式对Server程序进行Fuzz，其中的示例为Knot  DNS，由于DNS默认采用了UDP，所以其直接调用了sendto对程序本身的socket进行feed。然而如果是TCP模式这种方法就有一定的问题，比如上述的Nginx。

这里我认为可以有一种变通的解决思路，该方法理论上能够解决AFL在Fuzz无状态网络协议处理程序的先天不足。

假设有如下demo：
~~~C
#include <string.h> 
#include <sys/socket.h> 
#include <netinet/in.h> 
#include<arpa/inet.h> 
int main(void) { 
    int sockfd, clientfd; 
    socklen_t cliaddr_len; 
    struct sockaddr_in server_addr, client_addr; 
    sockfd = socket(AF_INET, SOCK_STREAM, 0); 
    if (sockfd == -1) { 
        perror("Something wrong\n"); 
        exit(1); 
    } 
    bzero(&server_addr, sizeof(server_addr)); 
    server_addr.sin_family = AF_INET; 
    server_addr.sin_port = htons(1024); 
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY); 

    int br = bind(sockfd, (struct sockaddr *) &server_addr, sizeof(server_addr)); 
    if (br == -1) { 
        perror("Something wrong\n"); 
        exit(1); 
    } 

    if ((listen(sockfd, 20)) == -1) { 
        perror("Something wrong\n"); 
        exit(1); 
    } 

    char buf[MAXLINE]; 
    for (;;) {
        clientfd = accept(sockfd, (struct sockaddr *) &client_addr, 
                &cliaddr_len); 
        printf("server get connection from %s.\n", inet_ntoa( 
                client_addr.sin_addr)); 
        int readize = 0; 
        while ((readize = read(clientfd, buf, MAXLINE)) > 0) { 
            printf("Content:%.*s", readize,buf); 
            printf("Length:%d...\n", readize); 
        } 
        write(clientfd, buf, readize); 
        close(clientfd); 
    } 
    return EXIT_SUCCESS; 
}
~~~
程序本身是一个简单的Server端的socket程序，其监听1024端口并接收数据，接收成功后将数据长度以及内容打印出来。

然而这样一个程序如果我们需要利用AFL对其进行Fuzz，则需要找到accept函数的调用部分并将其改为从本地文件读取内容。对于简单的socket程序我们可以这样做，然而对于复杂的大型程序来说，这显得不实际。

一种相对通用的方法是，首先定位accept，然后在accept之前创建一个线程，此线程所做的工作是从本地读取一个文件，并将其内容通过socket方式发送到原程序监听的端口上。我们将上述程序修改如下：
~~~C
#include <stdio.h> 
#include <stdlib.h> 
#include <unistd.h> 
#include <string.h> 
#include <sys/socket.h> 
#include <netinet/in.h> 
#include<arpa/inet.h> 
#include <pthread.h>  
#include<sys/time.h>
const int MAXLINE = 1024; 
void *thread(void *arg){
    int sockfd,sock_dt;
    struct sockaddr_in my_addr;
    struct sockaddr_in dest_addr;
    int destport =1024;
    int n_send_len;
    printf("thread is going to run and send sth to origin socket\n");
    sleep(1);
    sockfd=socket(AF_INET,SOCK_STREAM,0);
    dest_addr.sin_family=AF_INET;
    dest_addr.sin_port=htons(destport);
    dest_addr.sin_addr.s_addr=inet_addr("127.0.0.1");
    memset(&dest_addr.sin_zero,0,8);
    connect(sockfd,(struct sockaddr*)&dest_addr,sizeof(struct sockaddr));
    n_send_len = send(sockfd,"Content sent from thread\n",strlen("Content sent from thread\n"),0);
    printf("%d bytes sent\n",n_send_len);
    close(sockfd);
    return NULL;
}
int main(void) { 
    int sockfd, clientfd; 
    socklen_t cliaddr_len; 
    struct sockaddr_in server_addr, client_addr; 
    sockfd = socket(AF_INET, SOCK_STREAM, 0); 
    if (sockfd == -1) { 
        perror("Something wrong\n"); 
        exit(1); 
    } 
    bzero(&server_addr, sizeof(server_addr)); 
    server_addr.sin_family = AF_INET; 
    server_addr.sin_port = htons(1024); 
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY); 

    int br = bind(sockfd, (struct sockaddr *) &server_addr, sizeof(server_addr)); 
    if (br == -1) { 
        perror("Something wrong\n"); 
        exit(1); 
    } 

    if ((listen(sockfd, 20)) == -1) { 
        perror("Something wrong\n"); 
        exit(1); 
    } 

    char buf[MAXLINE]; 
    for (;;) { 
        pthread_t th;
        pthread_create(&th,NULL,thread,NULL);
        clientfd = accept(sockfd, (struct sockaddr *) &client_addr, 
                &cliaddr_len);
       sleep(1);
        printf("server get connection from %s.\n", inet_ntoa( 
                client_addr.sin_addr)); 
        int readize = 0; 
        while ((readize = read(clientfd, buf, MAXLINE)) > 0) { 
            printf("Content:%.*s", readize,buf); 
            printf("Length:%d...\n", readize); 
        } 
        write(clientfd, buf, readize); 
        close(clientfd); 
    } 
    return EXIT_SUCCESS; 
}   
~~~
可以看到我们在accept函数执行之前创建了线程，线程会主动发起连接请求并发送数据。
程序输出结果如下：
~~~shell
thread is going to run and send sth to origin socket
25 bytes sent
server get connection from 127.0.0.1.
Content:Content sent from thread
Length:25...
thread is going to run and send sth to origin socket
25 bytes sent
server get connection from 127.0.0.1.
Content:Content sent from thread
Length:25...
~~~
接下来我们以nginx为例来看下如何更改程序以便能够正常进行fuzz。在nginx中我们采用同样的思路，首先定位到main函数中并找到ngx_single_process_cycle函数的调用处，在上面的判断之前增加新线程。

~~~C
//AFL Thread Start @Puzzor 2015.08.03
    pthread_t th;
    pthread_create(&th,NULL,thread,NULL);
//AFL Thread End
~~~
除此之外，我们需要Nginx接收文件参数并读取文件中的请求内容
由于nginx本身是一个守护进程，因此我们需要在每次接收完请求后将nginx关闭以进行下一次fuzz，于是线程处理函数这样：
~~~C
void *thread(void *arg){
    int sockfd;
    struct sockaddr_in dest_addr;
    int destport =8080;
    sleep(0.5);
    sockfd=socket(AF_INET,SOCK_STREAM,0);
    dest_addr.sin_family=AF_INET;
    dest_addr.sin_port=htons(destport);
    dest_addr.sin_addr.s_addr=inet_addr("127.0.0.1");
    memset(&dest_addr.sin_zero,0,8);
    connect(sockfd,(struct sockaddr*)&dest_addr,sizeof(struct sockaddr));
    send(sockfd,"hello\n\n",strlen("hello\n\n"),0);
    close(sockfd);
    exit(0);
    return NULL;
}
~~~
修改完成后我们就可以利用AFL对Nginx进行Fuzz了，但是还需要注意的是目前我们只能够单进程进行Fuzz，因为在nginx.conf中只配置了一个端口，如果进行并行Fuzz会出现不同的变异样本发送到同一Server端，造成潜在的异常。因此如果利用AFL进行并行Fuzz，我们需要为每一个进程指定不同的conf文件，这一点可以利用”-c”参数。除此之外，我们需要传递端口参数以便线程发送数据时发送到相应的端口上。ngx_get_options函数中添加代码如下：
~~~C
//AFL Read File Option Start @Puzzor 2015.08.03
           case 'r':
              if (*p) {
                    AFL_File = (char *)p;
                }
              else{
                  AFL_File=argv[++i];
              }
              break;
//AFL Read File Option End
~~~
最后，目前只解决了免去对程序大量分析的工作，然而在优化上还可以继续深入，比如可以和persistent mode 相结合以提高单进程Fuzz效率。