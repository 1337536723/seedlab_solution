#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <netdb.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define NAME_LENGTH 100
#define PASSWORD_LENGTH 100
#define BUFF_SIZE 10000
// #define DEBUG

// as defined in tlsclient.c
#define CHK_SSL(err)             \
  if ((err) < 1) {               \
    ERR_print_errors_fp(stderr); \
    exit(2);                     \
  }
#define CA_DIR "ca_client"

// declaration
void endRequest();

// global variant
SSL *ssl;
struct sockaddr_in peerAddr;

int createTunDevice() {
  int tunfd;
  struct ifreq ifr;

  memset(&ifr, 0, sizeof(ifr));
  ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
  tunfd = open("/dev/net/tun", O_RDWR);
  ioctl(tunfd, TUNSETIFF, &ifr);
  return tunfd;
}

void tunSelected(int tunfd, int sockfd, SSL *ssl) {
  int len;
  char buff[BUFF_SIZE];

#ifdef DEBUG
  printf("Got a packet from TUN\n");
#endif

  bzero(buff, BUFF_SIZE);
  len = read(tunfd, buff, BUFF_SIZE);
  if (len <= 0) return;
  buff[len] = '\0';
  SSL_write(ssl, buff, len);
}

void socketSelected(int tunfd, int sockfd, SSL *ssl) {
  int len;
  char buff[BUFF_SIZE];

#ifdef DEBUG
  printf("Got a packet from the tunnel\n");
#endif

  bzero(buff, BUFF_SIZE);
  len = SSL_read(ssl, buff, BUFF_SIZE);
  if (len <= 0) return;
  buff[len] = '\0';
  write(tunfd, buff, len);
}

void endRequest() {
  if (ssl != NULL) {
    SSL_shutdown(ssl);
    SSL_free(ssl);
  }
  exit(0);
}

int verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx) {
  char buf[300];

  X509 *cert = X509_STORE_CTX_get_current_cert(x509_ctx);
  X509_NAME_oneline(X509_get_subject_name(cert), buf, 300);
#ifdef DEBUG
  printf("subject= %s\n", buf);
#endif
  if (preverify_ok == 1) {
    printf("Verification passed.\n");
  } else {
    int err = X509_STORE_CTX_get_error(x509_ctx);
    printf("Verification failed: %s.\n", X509_verify_cert_error_string(err));
    endRequest();
  }
}

SSL *setupTLSClient(const char *hostname) {
  // Step 0: OpenSSL library initialization
  // This step is no longer needed as of version 1.1.0.
  SSL_library_init();
  SSL_load_error_strings();
  SSLeay_add_ssl_algorithms();

  SSL_METHOD *meth;
  SSL_CTX *ctx;
  SSL *ssl;

  meth = (SSL_METHOD *)TLSv1_2_method();
  ctx = SSL_CTX_new(meth);

  // SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
  if (SSL_CTX_load_verify_locations(ctx, NULL, CA_DIR) < 1) {
    printf("Error setting the verify locations. \n");
    exit(0);
  }
  ssl = SSL_new(ctx);

  X509_VERIFY_PARAM *vpm = SSL_get0_param(ssl);
  X509_VERIFY_PARAM_set1_host(vpm, hostname, 0);

  return ssl;
}

int setupTCPClient(const char *hostname, int port) {
  struct sockaddr_in server_addr;

  // Get the IP address from hostname
  struct hostent *hp = gethostbyname(hostname);

  // Create a TCP socket
  int sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

  // Fill in the destination information (IP, port #, and family)
  memset(&server_addr, '\0', sizeof(server_addr));
  memcpy(&(server_addr.sin_addr.s_addr), hp->h_addr, hp->h_length);
  server_addr.sin_port = htons(port);
  server_addr.sin_family = AF_INET;

  // Connect to the destination
  connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr));
  return sockfd;
}

void login(SSL *ssl) {
  char username[NAME_LENGTH];
  char password[PASSWORD_LENGTH];
  char request[BUFF_SIZE];
  char reply[BUFF_SIZE];
  int len;

  printf("Your username:\n");
  scanf("%s", username);
  getchar();
  printf("Your password:\n");
  scanf("%s", password);

#ifdef DEBUG
  printf("Username: %s\nPassword: %s\n", username, password);
#endif

  // request
  bzero(request, BUFF_SIZE);
  strcpy(request, username);
  strcat(request, " ");
  strcat(request, password);
  len = strlen(username) + strlen(password) + 1;
  request[len] = '\0';

#ifdef DEBUG
  printf("Request: %s\tLen: %d\n", request, len);
#endif

  SSL_write(ssl, request, len);

  // check reply
  bzero(reply, BUFF_SIZE);
  len = SSL_read(ssl, reply, BUFF_SIZE - 1);
  reply[len] = '\0';

  // fail
  if (strcmp(reply, "success")) {
    printf("Login Failed\n");
    endRequest();
  }
  // success
}

int main(int argc, char *argv[]) {
  int tunfd;
  tunfd = createTunDevice();

  char *hostname = "serverguan.com";
  int port = 4433;

  if (argc > 1) hostname = argv[1];
  if (argc > 2) port = atoi(argv[2]);

  /*----------------TLS initialization ----------------*/
  ssl = setupTLSClient(hostname);
  printf("TLS Initialized\n");

  /*----------------Create a TCP connection ---------------*/
  int sockfd = setupTCPClient(hostname, port);
  printf("TCP Connected\n");

  /*----------------TLS handshake ---------------------*/
  SSL_set_fd(ssl, sockfd);
  int err = SSL_connect(ssl);
  CHK_SSL(err);
  printf("SSL connection is successful\n");
  printf("SSL connection using %s\n", SSL_get_cipher(ssl));

  login(ssl);

  while (1) {
    fd_set readFDSet;

    FD_ZERO(&readFDSet);
    FD_SET(sockfd, &readFDSet);
    FD_SET(tunfd, &readFDSet);
    select(FD_SETSIZE, &readFDSet, NULL, NULL, NULL);

    if (FD_ISSET(tunfd, &readFDSet)) tunSelected(tunfd, sockfd, ssl);
    if (FD_ISSET(sockfd, &readFDSet)) socketSelected(tunfd, sockfd, ssl);
  }
}
