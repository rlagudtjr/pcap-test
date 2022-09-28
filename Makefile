LDLIBS += -lpcap

all: pcap-test

pcap-test: pcap-test.cpp pcap-test.h

clean:
	rm -f pcap-test *.o

