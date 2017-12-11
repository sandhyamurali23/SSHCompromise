"""
Rashmi Dodeja
Sandhya Murali
Shristika Yadav


ATTACK PHASE
"""
import socket
import sys
import threading

# Create a TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# Connect the socket to the port where the server is listening
listActiveDaemon = [('localhost',10002)]

class myThread (threading.Thread):
   def __init__(self, threadID, name):
      threading.Thread.__init__(self)
      self.threadID = threadID
      self.name = name

   def run(self):
      print("Starting " + self.name)
      attack(listActiveDaemon[self.threadID-1])

def attack(address):
    """
    after scanning all the active ports, setup connection with the active daemon and try authentications.
    :param address: address on which attack will take place.
    :return:
    """
    try:
        flag_close = True

        while True:
            if (flag_close == True):
                server_address = (address)
                print('connecting to %s port %s' % server_address)
                sock.connect(server_address)
                flag_close = False

            ques = sock.recv(16)
            if ques == 'SUCCESS':
                break
            if (ques != "NACK"):
                ans = raw_input(ques + '\t')
                sock.sendall(ans)
            else:
                sock.sendall("NACK")
                flag_close = True
                break
        try:
            first_iter = 0
            ans=''
            if ques == 'SUCCESS':
                print('CONNECTION SUCCESSFUL')
                while True:
                    if first_iter != 0:
                        print('waiting')
                        ques = sock.recv(16)
                    print(ques)
                    if ans !='CLOSE ALL' and (ques != "NACK"):
                        ans = raw_input('Received ACK' + '\n')
                        sock.sendall(ans)
                        first_iter += 1
                    else:
                        if ques=='NACK':
                            print('Closing Connection')
                        #sock.sendall("NACK")
                        #flag_close = True
                            break
        except KeyboardInterrupt:
            sock.sendall("NACK")


    finally:
        print(sys.stderr, 'closing socket')
        sock.close()

def main():
    threadList = []
    # no of active deamon
    noOfActiveDeamon = len(listActiveDaemon)

    # create thread list
    for idx in range(noOfActiveDeamon):
        threadList.append("thread"+str(idx))

    threadID = 1
    threads = []

    # create new thread
    for tName in threadList:
        thread = myThread(threadID, tName)
        thread.start()
        threads.append(thread)
        threadID += 1

if __name__=="__main__":
    main()
