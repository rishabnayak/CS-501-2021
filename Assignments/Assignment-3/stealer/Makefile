CC=gcc
CXX=g++
LDFLAGS=  -static -lshell32  -lshlwapi -lcrypt32 -lbcrypt -municode
PDB=-g
BIN=bin
ifeq ($(OS),Windows_NT)
	RM=powershell /c rm
else
	RM=rm
endif

# all: aesgcm sqlite3 stealer

all: sqlite3 stealer

# run sqlite3 before
stealer:
	$(CXX)  stealer.cpp sqlite3.o $(LDFLAGS) -o stealer.exe
# stealer:
# 	$(CXX)  stealer.cpp aes_gcm.o sqlite3.o $(LDFLAGS) -o stealer.exe
# aesgcm:
# 	$(CC) -c ..\aes_gcm\aes_gcm.cpp
sqlite3:
	$(CC) -lcrypt32 -lbcrypt -municode -c sqlite3.c
clean:
	$(RM) *.exe 
	$(RM) *.o