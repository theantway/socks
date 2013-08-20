#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

int main() {
  register int s;
  register int bytes;
  struct sockaddr_in sa;
  char buffer[BUFSIZ+1];

  if ((s = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
    perror("socket");
    return 1;
  }

  bzero(&sa, sizeof sa);

  sa.sin_family = AF_INET;
  sa.sin_port = htons(9999);
  sa.sin_addr.s_addr = htonl((((((127 << 8) | 0) << 8) | 0) << 8) | 1);

  printf("sizeof sa: %d\n", sizeof sa);
  
  if (connect(s, (struct sockaddr *)&sa, sizeof sa) < 0) {
    perror("connect");
    close(s);
    return 2;
  }

  do {
    write(1, buffer, bytes);    
  }while ((bytes = read(s, buffer, BUFSIZ)) > 0);
    

  close(s);
  return 0;
}