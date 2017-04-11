import socket
import ConfigParser, os
import sys

class RDServiceClient:

	def __init__(self):
		self.app_name="UIDAI SECURITY TEST APP"
		config = ConfigParser.ConfigParser()
		config.read('conf.ini')		
		self.start_port=config.getint('main','start_port')
		self.end_port=config.getint('main','end_port')
		self.current_port = self.start_port
		self.protocol = config.get('main','protocol')
		#START, DISCOVER, ATTACK
		self.status = 'START'
		#Sub module for Attacks
		self.module = ''
		#Let us not kill ourself trying to read all the data back from the RD Service.
		#So we will read only the respective buffer size to validate.
		self.total_buffer = config.getint('main','buffer')
		self.host = config.get('main','host')
		#in Seconds
		self.socket_timeout=config.getfloat('main','timeout')
		self.service = []
		print "Initialized " + self.app_name + " for " + self.host + ":" + str(self.start_port) + " - " + str(self.end_port)


	#TODO:Should return back all available services, thir port number, this name and their services
	def discover_rd_services(self):
		print "Attempting to discover"
		prev_size = 0
		while self.current_port <= self.end_port:
			#print('\r' * prev_size, end='')
			print("Port: " + str(self.current_port))
			prev_size = len("Port: " + str(self.current_port))
			if(self.connect_rd_services(self.current_port)!=0):
				print "We found a service so please parse it"

			self.current_port = self.current_port+1
		#Let us reset it back to the normal
		self.current_port = self.start_port

	def get_socket(self,host,port):
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.settimeout(self.socket_timeout)
		s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)				
		s.connect((host,port))		
		return s

	def connect_rd_services(self,port):
		try:
			s = self.get_socket(self.host,port)		
			s.send("RD-SERVICE * HTTP/1.1%s" % (CRLF))
			s.send("HOST: " + self.host + ":"+port+"%s" % (CRLF))
			s.send("EXT: "+self.app_name % (CRLF))
			data = (s.recv(self.total_buffer))
			print data
			# TODO: The data has to be parsed and RD service details should be obtained.

			# https://docs.python.org/2/howto/sockets.html#disconnecting
			s.shutdown(1)
			s.close()
		except socket.error,exc:
			return 0

	def capture_command(self,path,port,attack_file_full_path):
		f = open(attack_file_full_path,'rb')

		s = self.get_socket(self.host,port)
		s.send("CAPTURE " + self.protocol + "://" +self.host + ":" + port+path %(CRLF) )
		s.send("HOST: " + self.host + ":"+port+"%s" % (CRLF))
		l = f.read(1024)
		while (l):    
			s.send(l)
			l = f.read(1024)
			f.close()
			data = (s.recv(self.total_buffer))
			print data
		s.shutdown(1)
		s.close()
		# TODO: The data has to be parsed and RD service details should be obtained.
		

	def device_info_command(self,path,port,attack_file_full_path):
		f = open(attack_file_full_path,'rb')

		s = self.get_socket(self.host,port)
		s.send("DEVICEINFO " + self.protocol + "://" +self.host + ":" + port+path %(CRLF) )
		s.send("HOST: " + self.host + ":"+port+"%s" % (CRLF))
		l = f.read(1024)
		while (l):    
			s.send(l)
			l = f.read(1024)
			f.close()
			data = (s.recv(self.total_buffer))
			print data
	# TODO: The data has to be parsed and RD service details should be obtained.

	# https://docs.python.org/2/howto/sockets.html#disconnecting
		s.shutdown(1)
		s.close()    	

