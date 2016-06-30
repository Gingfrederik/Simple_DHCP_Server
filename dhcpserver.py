from socket import *
import sys
import base64
import struct
import select
import binascii

myaddr = gethostbyname(gethostname())
boardcast = "255.255.255.255"
BOOTP_CLIENT = 68
BOOTP_SERVER = 67
lxid = 0
def macunpack(data):
    s = data
    return ':'.join([s[i:i+2].decode('ascii')  for i in range(0, 12, 2)])

def slicendice(msg,slices): 
    for x in slices:

        yield msg[:x]
        msg = msg[x:]

def reqparse(message): 
    
    global lxid
    data=None
    dhcpfields=[1,1,1,1,4,2,2,4,4,4,4,6,10,192,4,255,1,None]

    messagesplit=[binascii.hexlify(x) for x in slicendice(message,dhcpfields)]
    XID = struct.unpack('!I', message[4:8])[0]
    client_mac = macunpack(messagesplit[11])
    dhcpopt=int(messagesplit[15][5:6])
     
    
    if dhcpopt == 1:
        print(lxid)
        print("""dhcpopt: {c}
client_mac: {b}
XID: {x}
""".format(b=client_mac,x= XID,c=dhcpopt))

        data = b""
        data += b'\x02' #op
        data += b'\x01' #HType
        data += b'\x06' #HLen
        data += b'\x00' #Hops
        data += message[4:8] #XID
        data += b'\x00\x00\x00\x00' #Secs&Flags
        data += b'\x00'*4 #CIAddr
        data += inet_aton('192.168.1.99') #YIAddr
        data += b'\x00\x00\x00\x00' #SIAddr
        data += b'\x00'*4 #GIAddr
        data += message[28:34] #CHAddr
        data += b'\x00'*10+b'\x00'*192 #SName&File
        data += b'\x63\x82\x53\x63' #magic cookie
        data += b'\x35\x01\x02' #message-type
        data += b'\x01\x04'+b'\xff\xff\xfe\x00' #Subnet Mask 1
        data += b'\x36\x04'+inet_aton(myaddr) #Server identifier 54
        data += b'\x1c\x04'+inet_aton(boardcast)  #Broadcast Address 28
      #  data += b'\x03\x04'+b'\x8c\x87\xff\xfe' #Router 3
        data += b'\x33\x04'+b'\x00\x00\x1c\x20' #IP address lease time 51
        data += b'\xFF\x00'
        lxid = (struct.unpack('!I', data[4:8])[0])
        broadcast_socket.sendto(data, ('255.255.255.255', BOOTP_CLIENT))
        print('\033[31m')
        print('Offer Send\n')
        print('\033[0m')

    elif dhcpopt == 3 and XID == lxid:
        print(lxid)
        print("""dhcpopt: {c}
client_mac: {b}
XID: {x}
""".format(b=client_mac,x= XID,c=dhcpopt))

        data = b""
        data += b'\x02' #op
        data += b'\x01' #HType
        data += b'\x06' #HLen
        data += b'\x00' #Hops
        data += message[4:8] #XID
        data += b'\x00\x00\x00\x00' #Secs&Flags
        data += b'\x00'*4 #CIAddr
        data += inet_aton('192.168.1.99') #YIAddr
        data += b'\x00\x00\x00\x00' #SIAddr
        data += b'\x00'*4 #GIAddr
        data += message[28:34] #CHAddr
        data += b'\x00'*10+b'\x00'*192 #SName&File
        data += b'\x63\x82\x53\x63' #magic cookie
        data += b'\x35\x01\x05' #message-type
        data += b'\x01\x04'+b'\xff\xff\xfe\x00' #Subnet Mask 1
        data += b'\x36\x04'+inet_aton(myaddr) #Server identifier 54
        data += b'\x1c\x04'+inet_aton(boardcast)  #Broadcast Address 28
      #  data += b'\x03\x04'+b'\x8c\x87\xff\xfe' #Router 3
        data += b'\x33\x04'+b'\x00\x00\x1c\x20' #IP address lease time 51
        data += b'\xFF\x00'
        
        broadcast_socket.sendto(data, ('255.255.255.255', BOOTP_CLIENT))
        print('\033[32m')
        print('Ack Send\n')
        print('\033[0m')
       


if __name__ == '__main__':
    broadcast_socket = socket(type = SOCK_DGRAM)
    broadcast_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR,255 )
    broadcast_socket.setsockopt(SOL_IP, SO_REUSEADDR ,255)
    broadcast_socket.setsockopt(SOL_SOCKET, SO_BROADCAST,255)
    broadcast_socket.bind(('0.0.0.0', BOOTP_CLIENT))
    
    sock = socket(type = SOCK_DGRAM)
    sock.setsockopt(SOL_IP, SO_REUSEADDR, 1)
    sock.bind(('',BOOTP_SERVER))
    print(myaddr)
    print ('\nSocket started\n')
    while 1:
        reads = select.select([sock],[],[],1)[0]
        for s in reads:
            packet ,addr= sock.recvfrom(4096)
            packet = reqparse(packet)
            

            
