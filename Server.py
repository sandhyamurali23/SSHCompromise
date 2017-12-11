"""
Rashmi Dodeja
Sandhya Murali
Shristika Yadav


BRUTE FORCE PHASE AND COMPROMISE DETECTION PHASE.
"""
import socket,sys
import time
import datetime
import threading

socketDist={}
socks=[]
threads = []
connects = []
i=0
username_host='sandhya'
password_host='1234'
list_logs=[]
run_event = threading.Event()
class Log:
    """
    Log created for storing log information about attacker
    """
    __slots__ = 'no_packets','conn_attempt_count','client_IP','auth_connection_successful','timestamp','total_packets'
    
    def __init__(self,conn_attempt_count,client_IP,timestamp,no_packets,total_packets):
            self.conn_attempt_count=conn_attempt_count
            self.client_IP=client_IP
            self.timestamp=timestamp
            self.no_packets=no_packets
            self.total_packets=total_packets

    def __str__(self):
        return 'Log: '+str(self.client_IP)+ ' '+ str(self.conn_attempt_count)

class CompromiseThread (threading.Thread):

    def __init__(self, threadID, name, counter,connection):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.counter = counter
        self.connection=connection
        self.data=None

    def run(self):
        while True:
            self.data = receive_data(self.connection)
            if self.data!=0 and self.data.strip() !='':
                print(self.data)
                self.connection.sendall("ACK")
                print('Received Data')
            else:
                break
            time.sleep(5)

    def fetch_Data(self):
        fdata = self.data
        self.data=None
        return fdata

class BruteforceThread (threading.Thread):

    def __init__(self, threadID, name,set):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.set = set

    def run(self):
        if self.set == True:
            bruteForce(self.threadID)
def scanThread(id):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_address = ('localhost', 10000 + id)
    print('starting up on %s port %s', server_address)
    sock.bind(server_address)
    sock.listen(1)
    # Wait for a connection
    print('waiting for a connection')
    connection, client_address = sock.accept()
    nack = connection.recv(16)
    if nack=='NACK':
        connection.close()
    sock.close()

def genuineConnection(connection):
    data=''
    try:
        while data!='NACK':
            data=connection.recv(16)
            print('Received Data', data)
            if data!='NACK':
                connection.sendall("ACK")
            else:
                connects.remove(connection)
                connection.close()
    except:
        print('Connection closed.')


def bruteForce(id):
    """
    Brute force phase
    :param id: thread id.
    :return:
    """
    # Create a TCP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    socks.append(sock)
    # Bind the socket to the port
    server_address = ('localhost', 10000+id)
    print('starting up on %s port %s', server_address)
    sock.bind(server_address)
    sock.listen(1)

    while True:
        # Wait for a connection
        print('waiting for a connection')
        connection, client_address = sock.accept()
        connects.append(connection)
        if len(connects)>1:
            print(connects[0].getsockname())
        flag_close=False

        flag_present=False
        for i in range(len(list_logs)):
            if(list_logs[i].client_IP[0]==client_address[0] and list_logs[i].client_IP[1]==client_address[1]):
                flag_present=True
                if(list_logs[i].conn_attempt_count>=5):
                    list_logs[i].timestamp=time.time()
                    index=i
                    while (True):
                        connection.sendall("NACK")
                        nack = connection.recv(16)
                        if (nack == "NACK"):
                            #connection.close()
                            flag_close = True
                            break
                    break
                else:
                    list_logs[i].conn_attempt_count+=1
                    list_logs[i].timestamp=time.time()
                    break

        if(flag_present==True and list_logs[index].conn_attempt_count>=5):
            break


        elif(flag_present==False):
            log=Log(1,client_address,time.time(),0,0)
            list_logs.append(log)

        try:
                while True:
                    for i in range(len(list_logs)):
                        if(list_logs[i].client_IP==client_address):
                            index=i
                            break

                    if(flag_close==True and list_logs[index].conn_attempt_count<5):
                        connection, client_address = sock.accept()
                        connects.append(connection)
                        print(connects[0].getsockname())
                        for i in range(len(list_logs)):
                            if(list_logs[i].client_IP==client_address):
                                index=i
                                break
                        list_logs[index].conn_attempt_count+=1
                        list_logs[index].timestamp=time.time()

                        flag_close=False

                    elif(flag_close==True and list_logs[index].conn_attempt_count>=5):
                        connection, client_address = sock.accept()
                        connection.sendall("NACK")
                        connection.close()
                        break

                    if(flag_close==False):
                        #print('connection from', client_address)
                        index=0
                        for i in range(len(list_logs)):
                            if(list_logs[i].client_IP==client_address):
                                index=i
                                break
                        #print(list_logs[index].no_packets,list_logs[index].total_packets)
                        connection.sendall("Enter username")
                        list_logs[index].no_packets+=1
                        list_logs[index].total_packets+=1
                        username = connection.recv(16)
                        list_logs[index].no_packets+=1
                        list_logs[index].total_packets+=1
                        connection.sendall("Enter password")
                        list_logs[index].no_packets+=1
                        list_logs[index].total_packets+=1
                        password = connection.recv(16)
                        list_logs[index].no_packets+=1
                        list_logs[index].total_packets+=1
                        print("Username Received",username)
                        print("Password Received",password)

                        if(username_host==username and password_host==password):
                            list_logs[index].auth_connection_successful=True
                            connection.sendall("SUCCESS")
                            list_logs[index].no_packets=0
                            if list_logs[index].conn_attempt_count>2:
                                compromise(client_address,connection,sock)
                            else:
                                genuineConnection(connection)
                            break
                            #successfull
                        else:
                            list_logs[index].auth_connection_successful=False

                            print(list_logs[index].client_IP,list_logs[index].no_packets )
                            if(list_logs[index].no_packets>=12):

                                list_logs[index].no_packets=0

                                while (True):
                                    connection.sendall("NACK")
                                    nack = connection.recv(16)
                                    if (nack == "NACK"):
                                        #connection.close()
                                        flag_close = True
                                        break
                        if(flag_close==True):
                            connects.remove(connection)
                            connection.close()


        finally:
            # Clean up the connection
            if connection in connects:
                connects.remove(connection)
            connection.close()


def receive_data(connection):
    """

    :param connection:
    :return:
    """
    data=0
    try:
        data=connection.recv(16)
    except:
        print('Connection closed from Client')
    return data


def compromise(client_address,connection,sock):
    """
    Compromise detection phase.
    """
    thread1 = CompromiseThread(1, "Thread-1", 1,connection)
    time_pkts_received=[]
    datasize_pkts_received=[]
    monitoring_start_time = datetime.datetime.now()
    connection_closed=False
    thread1.start()
    while datetime.datetime.now()<(monitoring_start_time + datetime.timedelta(minutes = 1)):
        data = thread1.fetch_Data()
        if data != None:
            if data != 0 and data !='':
                time_pkts_received.append(datetime.datetime.now())
                datasize_pkts_received.append(data)
                connection.sendall('ACK')
            else:
                thread1.join()
                # connection closed from client
                connection_end_time= datetime.datetime.now()
                connection_closed=True
                # Compromise phase detected, Instant logout, Continue dictionary
                if len(time_pkts_received)<1:
                    minutes,seconds=divmod((connection_end_time - monitoring_start_time).total_seconds(), 60)
                    no_of_pkts_per_time = len(time_pkts_received)/((minutes*60+seconds)*30)
                    log_received = None
                    for log in list_logs:
                        if log.client_IP[0] == client_address[0]:
                            log_received = log
                            break
                    if no_of_pkts_per_time<3 and log_received!=None and log_received.conn_attempt_count>2:
                        print("Compromise phase detected, Instant logout, Continue dictionary")
                    connects.remove(connection)
                    connection.close()
                # Compromise phase detected, Instant logout, Abort dictionary
                elif len(time_pkts_received)==1 and datasize_pkts_received[0] == 'CLOSE ALL':
                    log_received=None
                    for log in list_logs:
                        if log.client_IP[0] == client_address[0]:
                            log_received=log
                            break
                    if log_received!=None and log_received.conn_attempt_count>2:
                        log_received.auth_connection_successful = True
                        #connection.sendall("NACK")
                        #print('connection', connection.getsockname())
                        i=0
                        while len(connects)>1:
                            if connects[i]!=connection:
                                #print(connects[i].getsockname())
                                connects[i].sendall("NACK")
                                connects[i].close()
                                connects.pop(i)
                            else:
                                i+=1

                        for i in range(len(threads)):
                            threads[i].set=False

                        run_event.clear()

                        print('Compromise phase detected, Instant logout, Abort dictionary')
                        #print(connects[0].getsockname())
                        #connects.remove(connection)
                        connection.close()

                break
        else:
            time.sleep(.5)

    if not connection_closed:
        # monitored the traffic for 2 minutes.
        connection_end_time = datetime.datetime.now()
        # Compromise phase detected, Maintain connection, Continue dictionary.
        if datasize_pkts_received[0] != 'CLOSE ALL':
            minutes, seconds = divmod((connection_end_time - monitoring_start_time).total_seconds(), 60)
            no_of_pkts_per_time = len(time_pkts_received) / ((minutes * 60 + seconds) * 30)
            if no_of_pkts_per_time < 3:
                print("Compromise phase detected, Maintain connection, Continue dictionary \n Closing connection with Attacker")
                connection.sendall("NACK")
                connects.remove(connection)
                connection.close()
        # Compromise phase detected, Maintain connection, Abort dictionary.
        elif datasize_pkts_received[0] == 'CLOSE ALL':
            print("Compromise phase detected, Maintain connection, Abort dictionary \n Closing connection with Attacker")
            i = 0
            while len(connects) > 1:
                if connects[i] != connection:
                    connects[i].sendall("NACK")
                    connects[i].close()
                    connects.pop(i)
                else:
                    i += 1

            connection.close()

def main():
    #  Thread list
    threadList = [1,2,3,4,5]
    # thread connections per attacker.
    for i in range(len(threadList)):
        t=BruteforceThread(threadList[i], "Thread"+str(threadList[i]), True)
        threads.append(t)
    for i in range(len(threads)):
        threads[i].start()
        time.sleep(.5)

    try:
        while True:
            time.sleep(.1)
    except KeyboardInterrupt:
        run_event.clear()
        for i in range(len(threads)):
            threads[i].join()
        for i in range(len(connects)):
            connects[i].close()
        for i in range(len(socks)):
            socks[i].close()
        print("Threads successfully closed")

if __name__ == '__main__':
    main()



