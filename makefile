GPP = g++ -m32
GCC = gcc -m32

OUTFILE = "./bcrypt.so"

COMPILE_FLAGS = -c -O3 -w -D LINUX -I ./SDK/amx/ -fPIC
LIBRARIES = -pthread -lrt -Wl,-Bstatic -lboost_thread -lboost_chrono -lboost_system -lboost_atomic -Wl,-Bdynamic

all: bcrypt clean
	
clean:
	rm -f *~ *.o

bcrypt:
	$(GCC) $(COMPILE_FLAGS) src/crypt_blowfish/*.c
	$(GPP) $(COMPILE_FLAGS) src/SDK/*.cpp
	$(GPP) $(COMPILE_FLAGS) -std=c++0x src/*.cpp
	$(GPP) -O2 -fshort-wchar -shared -o $(OUTFILE) *.o $(LIBRARIES)

