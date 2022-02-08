obj-m += spkd.o
obj-m += dump-ssh-agent.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname _r)/build M=$(PWD) clean

