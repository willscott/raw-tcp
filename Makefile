serv : serv.c
	clang -o serv -I/usr/include/x86_64-linux-gnu -lpcap serv.c
