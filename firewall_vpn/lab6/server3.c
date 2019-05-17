#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>
#include <unistd.h>

#define BUFF_SIZE 2000
// #define DEBUG

#define CHK_SSL(err)               \
   if ((err) < 1)                  \
   {                               \
      ERR_print_errors_fp(stderr); \
      exit(2);                     \
   }

#define CHK_ERR(err, s) \
   if ((err) == -1)     \
   {                    \
      perror(s);        \
      exit(1);          \
   }

// global variant
struct sockaddr_in peerAddr;

// declaration
int setupTCPServer();                                 // Defined in Listing 19.10
void processRequest(int tunfd, SSL *ssl, int sockfd); // Defined in Listing 19.12
void endRequest(SSL *ssl, int conn);

int createTunDevice()
{
   int tunfd;
   struct ifreq ifr;
   memset(&ifr, 0, sizeof(ifr));

   ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

   tunfd = open("/dev/net/tun", O_RDWR);
   ioctl(tunfd, TUNSETIFF, &ifr);
   printf("TUN setup\n");
   return tunfd;
}

void tunSelected(int tunfd, int sockfd, SSL *ssl)
{
   int len;
   char buff[BUFF_SIZE];

   bzero(buff, BUFF_SIZE);
   len = read(tunfd, buff, BUFF_SIZE);
   buff[len] = '\0';
   SSL_write(ssl, buff, len);
}

// used to initiate the ssl
SSL *SSLInit()
{
   SSL_METHOD *meth;
   SSL_CTX *ctx;
   SSL *ssl;
   int err;

   SSL_library_init();
   SSL_load_error_strings();
   SSLeay_add_ssl_algorithms();

   meth = (SSL_METHOD *)TLSv1_2_method();
   ctx = SSL_CTX_new(meth);
   SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
   SSL_CTX_use_certificate_file(ctx, "./cert_server/serverguan.crt", SSL_FILETYPE_PEM);
   SSL_CTX_use_PrivateKey_file(ctx, "./cert_server/serverguan.key", SSL_FILETYPE_PEM);
   ssl = SSL_new(ctx);
   return ssl;
}

void socketSelected(int tunfd, int sockfd, SSL *ssl)
{
   int len;
   char buff[BUFF_SIZE];

   bzero(buff, BUFF_SIZE);
   len = SSL_read(ssl, buff, BUFF_SIZE);
   buff[len] = '\0';
   write(tunfd, buff, len);
}

void processRequest(int tunfd, SSL *ssl, int sockfd)
{
   while (1)
   {
      fd_set readFDSet;

      FD_ZERO(&readFDSet);
      FD_SET(sockfd, &readFDSet);
      FD_SET(tunfd, &readFDSet);
      select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);

      if (FD_ISSET(tunfd, &readFDSet))
         tunSelected(tunfd, sockfd, ssl);
      if (FD_ISSET(sockfd, &readFDSet))
         socketSelected(tunfd, sockfd, ssl);
   }
}

void endRequest(SSL *ssl, int conn)
{
   if (ssl != NULL)
   {
      SSL_shutdown(ssl);
      SSL_free(ssl);
   }
   close(conn);
}

int setupTCPServer()
{
   struct sockaddr_in sa_server;
   int listen_sock;

   listen_sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
   CHK_ERR(listen_sock, "socket");
   memset(&sa_server, '\0', sizeof(sa_server));
   sa_server.sin_family = AF_INET;
   sa_server.sin_addr.s_addr = INADDR_ANY;
   sa_server.sin_port = htons(4433);
   int err = bind(listen_sock, (struct sockaddr *)&sa_server, sizeof(sa_server));
   CHK_ERR(err, "bind");
   err = listen(listen_sock, 5);
   CHK_ERR(err, "listen");
   printf("TCP Setup\n");
   return listen_sock;
}


int main(int argc, char *argv[])
{

   size_t client_len;
   struct sockaddr_in sa_client;

   int tunfd = createTunDevice();
   int sockfd = setupTCPServer();


   while (1)
   {
      int conn = accept(sockfd, (struct sockaddr *)&sa_client, &client_len);
      if (fork() == 0)
      {
         close(sockfd);

         printf("%d: Start\n", getpid());
         SSL *ssl = SSLInit();
         SSL_set_fd(ssl, conn);
         int err = SSL_accept(ssl);
         int errcode = SSL_get_error(ssl, err);

         printf("%d: Handshake\n", getpid());
         CHK_SSL(err);
         printf("%d: Working\n", getpid());
         processRequest(tunfd, ssl, conn);

         printf("%d: Exit\n", getpid());
         endRequest(ssl, conn);
         return 0;
      }
      else
      {
         close(conn);
         close(tunfd);
      }
   }
}
