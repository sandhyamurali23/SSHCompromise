"""
Rashmi Dodeja
Sandhya Murali
Shristika Yadav

Scanning all the active daemons. (SCAN PHASE)
"""
import socket
import sys
import threading, random, struct, time, select,logging,netaddr

# Create a TCP/IP socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listDaemons = [('localhost',10001)]



# Connect the socket to the port where the server is listening
listActiveDaemon = []

class myThread (threading.Thread):
   def __init__(self, threadID, name):
      threading.Thread.__init__(self)
      self.threadID = threadID
      self.name = name

   def run(self):
      #print("Starting " + self.name)
      time.sleep(1)
      #attack(listActiveDaemon[self.threadID-1])

def attack(address):
    """
    brute force attack
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

def checkActiveDaemons():
    """

    :return:
    """
    for i in range(len(listDaemons)):
        if (check_port_open(listDaemons[i][0], int(listDaemons[i][1]))):
            listActiveDaemon.append((listDaemons[i][0], int(listDaemons[i][1])))

def check_port_open(ipaddress,port):
    """
    Checking for all the active ports. (SCAN PHASE)
    """
    #ip=str(ipaddress)
    #print(ip)
    #ip=ipaddress.exploded
    s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.3)

    try:
        s.connect((ipaddress,port))
        #socket_raw = create_raw_socket()
        #packet_id = int((id(random.random()) % 65535))  # create packet id
        #flag_send = send_ping(ipaddress, socket_raw, packet_id, 65)  # send ping
        #if(flag_send==1):
            #response = receive_ping(socket_raw, packet_id, time.time(), 2)  # receive ping
            #if(response==None):
                #return
        s.sendall('NACK')
        print(ipaddress,port,'is online')

    except (socket.timeout, socket.error):
        print('no connection to {} {}'.format(str(ipaddress), port))
        print('exit')
        return

    s.close()
    return True


def send_ping(dest_address, socket_raw, packet_id, packet_size):
    '''
    Sends ping to destination
    @param: dest_address : destination address
    @param: socket_raw: raw socket
    @param: packet_id: packet id
    @param: packet_size: packet size
    @return 1: if packet sent successfully, 0 otherwise

    '''
    if (packet_size % 2 == 1):
        packet_size = packet_size + 1

    header = struct.pack("bbHHh", 8, 0, 0, packet_id, 1)  # pack the icmp header
    data = b'12' * packet_size  # create data in bytes
    packet = header + data

    checksum = compute_checksum(header + data)  # compute checksum
    checksum_htons = socket.htons(checksum)  # convert checksum to host to network
    header = struct.pack("bbHHh", 8, 0, socket.htons(checksum_htons), packet_id,1)  # pack the resultant checksum

    total_data = header + data

    try:

        socket_raw.setsockopt(socket.SOL_IP, socket.IP_TTL, 255)  # create IP header with ttl 255
        socket_raw.sendto(total_data, (socket.gethostbyname(dest_address), 1))  # send packet to destination
        return 1
    except:
        return 0

def create_raw_socket():
    '''
    Creates raw socket using icmp header
    @param: dest_address : destination address
    @return: socket_raw: raw socket

    '''

    icmp = socket.getprotobyname("icmp")  # gets icmp icmp protocol

    try:
        socket_raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)  # creates raw socket
    except socket.error:
        msg = 'ICMP failure'
        print('Socket could not be created. Error Code : ' + msg)
        sys.exit()

    return socket_raw

def receive_ping(socket_raw, packet_id, time_sent_packet, timeout_threshold):
    '''
    Receive ping from source
    @param: socket_raw: raw socket
    @param: packet_id: packet id
    @param: time_sent: time the packet was sent
    @param: timeout_threshold: timeout value
    @return: list_contents: list of values needed to display in ping

    '''

    while True:

        ready_state = select.select([socket_raw], [], [], timeout_threshold)  # determine the data from the socket

        if (ready_state[0] == []):  # if no data
            return

        time_receive_packet = time.time()  # time packet is received
        packet, address = socket_raw.recvfrom(1024)  # receive 1024 byte data

        icmp_header = packet[20:28]  # get icmp header

        ip_header = packet[0:20]  # get ip header

        ip_header_data = struct.unpack('!BBHHHBBH4s4s', ip_header)  # unpack ip header
        ttl = ip_header_data[5]  # get ttl value packed

        type, code, checksum, packetID, sequence = struct.unpack("bbHHh", icmp_header)  # unpack icmp header

        if (packetID == packetID):  # check packet ID
            round_trip_time = time_receive_packet - time_sent_packet  # compute round trip time and append contents
            list_contents = []
            list_contents.append(round_trip_time)
            list_contents.append(ttl)
            list_contents.append(address)
            return list_contents

def compute_checksum(source_string):
    '''
    Computes checksum
    @param: data : header+data value
    @return checksum value

    '''

    sum = 0
    count_to = (len(source_string) / 2) * 2
    count = 0
    while count < count_to:
        this_val = ord(source_string[count + 1]) * 256 + ord(source_string[count])
        sum = sum + this_val
        sum = sum & 0xffffffff  # Necessary?
        count = count + 2
    if count_to < len(source_string):
        sum = sum + ord(source_string[len(source_string) - 1])
        sum = sum & 0xffffffff  # Necessary?
    sum = (sum >> 16) + (sum & 0xffff)
    sum = sum + (sum >> 16)
    answer = ~sum
    answer = answer & 0xffff
    # Swap bytes. Bugger me if I know why.
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer

def getNetworkIp():
    """
    For scanning the active ports. Network ip is calculated.
    :return:
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.connect(('8.8.8.8', 80))
    return s.getsockname()[0]

def scan_active_ports(local_ip_address, port):
    """
    For scanning all the active ports.
    """
    ip = netaddr.IPNetwork('129.21.74.52/255.255.252.0')
    ipList=list(ip)
    for i in range(5):
        print(ipList[i])

def main():
    threadList = []
    ip_local = getNetworkIp()

    scan_active_ports(ip_local,22)
    # no of active deamon
    checkActiveDaemons()
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
