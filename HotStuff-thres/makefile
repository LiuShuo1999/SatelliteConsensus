all: sha2.o uECC.o thres_sig.o ipc.o comm.o config.o hotstuff.c
	gcc -o hotstuff hotstuff.c sha2.o uECC.o thres_sig.o ipc.o comm.o config.o -l pthread ./core.a
sha2.o: sha2.c
	gcc -o sha2.o -c sha2.c
uECC.o: uECC.c
	gcc -o uECC.o -c uECC.c
thres_sig.o: thres_signature.c 
	gcc -o thres_sig.o -c thres_signature.c
ipc.o: ipc.c
	gcc -o ipc.o -c ipc.c
comm.o: comm.c
	gcc -o comm.o -c comm.c
config.o: config.c
	gcc -o config.o -c config.c
clean:
	rm hotstuff main.o sha2.o uECC.o ipc.o thres_sig.o comm.o config.o