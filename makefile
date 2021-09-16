EXECUTABLE = mqtt_service
PRODUCT_NAME = Light MQTT Service
PRODUCT_VERSION = 0.9.1.0
FLAGS = -Wall -O3 -std=c++11

ifeq ($(QUEUE), 1)
	SERVICE_DEFINES += -DSERVICE_OPERATION_MODE_QUEUE
endif

all: mqtt_service.o service.o protocol.o thread.o
	g++ -lpthread -o $(EXECUTABLE) mqtt_service.o service.o protocol.o thread.o

install: $(EXECUTABLE)
	install $(EXECUTABLE) /usr/sbin
	cp mqtt_service.service /lib/systemd/system
	sed -i 's/{EXECUTABLE}/$(EXECUTABLE)/g' /lib/systemd/system/mqtt_service.service
	sed -i 's/{PRODUCT_NAME}/$(PRODUCT_NAME)/g' /lib/systemd/system/mqtt_service.service
	ln -s /lib/systemd/system/mqtt_service.service /etc/systemd/system/mqtt_service.service

mqtt_service.o: mqtt_service.cpp
	g++ $(FLAGS) -DPRODUCT_NAME="\"$(PRODUCT_NAME)\"" -DPRODUCT_VERSION="\"$(PRODUCT_VERSION)\"" $(SERVICE_DEFINES) -c mqtt_service.cpp

service.o: mqtt/service.cpp
	g++ $(FLAGS) $(SERVICE_DEFINES) -c mqtt/service.cpp

protocol.o: mqtt/protocol.cpp
	g++ $(FLAGS) -c mqtt/protocol.cpp

thread.o: thread/thread.cpp
	g++ $(FLAGS) -c thread/thread.cpp

clean:
	rm *.o
