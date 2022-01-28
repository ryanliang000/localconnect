all : client regsrv regcli regfix 
client : client.cpp
	gcc -DRUN -O2 -o $@ $^ -I../include -lpthread

regsrv : regsrv.cpp
	gcc -DRUN -O2 -o $@ $^ -I../include -lpthread

regcli : regcli.cpp
	gcc -DRUN -O2 -o $@ $^ -I../include -lpthread

regfix : regcli.cpp
	gcc -DRUN -DREGFIX -O2 -o $@ $^ -I../include -lpthread

clean : 
	rm client regsrv regcli regfix
