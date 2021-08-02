LDLIBS=-lpcap

all: send-arp-test

#Get_my_IP.o : Get_my_IP.h

send-arp-test: main.o arphdr.o ethhdr.o ip.o mac.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

#Get_my_IP.o : main.cpp Get_my_IP.h
#	gcc -c -o Get_my_IP.h

clean:
	rm -f send-arp-test *.o
