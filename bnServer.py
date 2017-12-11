"""
Rashmi Dodeja
Sandhya Murali
Shristika Yadav

backbone router
"""
import socket
import sys
import threading
import thread



class Node:
    __slots__ ='list_ip_dest','src_ip'

    def __init__(self,source_ip):
        self.src_ip=source_ip
        self.list_ip_dest=[]


class myThread(threading.Thread):
    def __init__(self, threadID, name, counter):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.name = name
        self.counter = counter

    def run(self):
        communicate(1)

def communicate(num):
    # once conenction is maintained.
    while True:
        ques = sockDaemon[num].recv(1024)
        print ques
        if ques != "NACK1":
            c.sendall(ques)
            sockDaemon[num].sendall(c.recv(1024))
        else:
            c.sendall("NACK1")
            num += 1
            break

# create a socket object
s = socket.socket()
num = 0
sockDaemon = []

print "Socket successfully created"
server_address = ('0.0.0.0', 12341)
s.bind(server_address)
print "socket binded to %s", server_address

# put the socket into listening mode
s.listen(5)
print "socket is listening"

list_ip=[]

c, addr = s.accept()
print 'Got connection from', addr
c.sendall('ACK ')

while True:
   username = c.recv(1024)
   print "username ",username
   username = username.split("$")
   print "received ",username,len(list_ip)

   flag_present=False
   for i in range(len(list_ip)):
       if (list_ip[i].src_ip == addr):
           flag_present=True
           break

   flag_make_connection = True
   for i in range(len(list_ip)):
       # if connection made by an attacker/genuine user inceases a threshold, close the connection.
       if (len(list_ip[i].list_ip_dest) >= 2):
           print "CLOSING EVERYTHING"
           sockDaemon[0].sendall("NACK")
           sockDaemon[1].sendall("NACK")
           c.sendall("NACK")
           c.close()
           sys.exit()
           flag_present = True
           flag_make_connection = False
       else:
           list_ip[i].list_ip_dest.append(username)
           flag_present = True

   if (flag_present == False):
       # appending data in log files
       node = Node(addr)
       node.list_ip_dest.append(username)
       list_ip.append(node)

   if(flag_make_connection==True):
        # if address is received from the attacker/genuine user.
        if(len(username) == 2):
           addr = (username[0], int(username[1].strip()))
           print "addr = ",addr
           p = socket.socket()
           p.connect(addr)
           thread1 = myThread(1, "Thread-1", 1)
           sockDaemon.append(p)


        else:
            print username