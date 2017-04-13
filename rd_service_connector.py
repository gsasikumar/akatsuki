import socket
import ConfigParser, os
import sys
from httplib import HTTPResponse
import datetime
from lxml import objectify

CONST_CRLF = '\r\n'
TEST_CASE_RESULT_TEMPLATE = "Test Case %s Status: %s"
TEST_CASE_RESULT_FAILURE = "Failure"
TEST_CASE_RESULT_PASS = "Pass"

class RDServiceClient:
	#CONST_CRLF = '\r\n'
	#TEST_CASE_RESULT_TEMPLATE = "Test Case %s Status: %s"
	#TEST_CASE_RESULT_FAILURE = "Failure"
	#TEST_CASE_RESULT_PASS = "Pass"

	def __init__(self):
		self.app_name="UIDAI"
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
		self.get_request_templates()		
		print "Initialized " + self.app_name + " for " + self.host + ":" + str(self.start_port) + " - " + str(self.end_port)

	def get_request_templates(self):
		#TODO: This is not the correct template. 
		return "RDSERVICE / HTTP/1.1 " + CONST_CRLF+"HOST: " + self.host + ":" +str(self.current_port)+" "+CONST_CRLF+"EXT: "+self.app_name+" " + CONST_CRLF + CONST_CRLF		

	def validate_discovery_headers(self,response):
		headers={}
		count =0
		for key, value in response.getheaders(): 
			headers[key]=value
			count=count+1
		if(count == 5):
			print TEST_CASE_RESULT_TEMPLATE % ("Header Count Validation for RD Service Discovery", TEST_CASE_RESULT_PASS)
		else:
			print TEST_CASE_RESULT_TEMPLATE % ("Header Count Validation for RD Service Discovery", TEST_CASE_RESULT_FAILURE)
			
		if('CACHE-CONTROL' in headers and headers['CACHE-CONTROL'] == "no-cache"):
			print TEST_CASE_RESULT_TEMPLATE % ("Cache Header Validation for RD Service Discovery", TEST_CASE_RESULT_PASS)
		else:
			print TEST_CASE_RESULT_TEMPLATE % ("Cache Header Validation for RD Service Discovery", TEST_CASE_RESULT_FAILURE)

		if('LOCATION' in headers and headers['LOCATION'] == "http://127.0.0.1:"+str(self.current_port)):
			print TEST_CASE_RESULT_TEMPLATE % ("LOCATION Header Validation for RD Service Discovery", TEST_CASE_RESULT_PASS)
		else:
			print TEST_CASE_RESULT_TEMPLATE % ("LOCATION Header Validation for RD Service Discovery", TEST_CASE_RESULT_FAILURE)

		if('Content-Type' in headers and headers['Content-Type'] == "text/xml"):
			print TEST_CASE_RESULT_TEMPLATE % ("Content-Type Header Validation for RD Service Discovery", TEST_CASE_RESULT_PASS)
		else:
			print TEST_CASE_RESULT_TEMPLATE % ("Content-Type Header Validation for RD Service Discovery", TEST_CASE_RESULT_FAILURE)

		if('Connection' in headers and headers['Connection:'] == "close"):
			print TEST_CASE_RESULT_TEMPLATE % ("Connection Header Closed for RD Service Discovery", TEST_CASE_RESULT_PASS)
		else:
			print TEST_CASE_RESULT_TEMPLATE % ("Connection Header Closed for RD Service Discovery", TEST_CASE_RESULT_FAILURE)

	#TODO:Should return back all available services, thir port number, this name and their services
	def discover_rd_services(self):
		print "Attempting to discover"
		prev_size = 0
		while self.current_port <= self.end_port:
			#print('\r' * prev_size, end='')
			#print("Port: " + str(self.current_port))
			prev_size = len("Port: " + str(self.current_port))
			response = self.connect_rd_services(self.current_port)
			if(response!=0):
				if(response.status !=200 ):
					print "Found invalid service on port " + self.current_port
					return 0
				print "Service found on port: " + str(self.current_port)
				print "Date: " + str(datetime.date.today().isoformat())				
				print "Response Status " + str(response.status)				
				

				return response

			self.current_port = self.current_port+1
		#Let us reset it back to the normal
		self.current_port = self.start_port
		print "No UIDAI RD SERVICE Found!!!!"
		return 0
		
	def print_device_info(self,response):
		dd_response_xml = objectify.fromstring(response.read())
		print "Device Info: " + dd_response_xml.get("info")

	def get_socket(self,host,port):
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.settimeout(self.socket_timeout)
		s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)				
		s.connect((host,port))		
		return s

	def connect_rd_services(self,port):
		try:
			s = self.get_socket(self.host,port)
			request_string = self.get_request_templates()
			#print request_string 
			s.sendall(request_string)
			data = HTTPResponse(s)
			#data = (s.recv(self.total_buffer))
			data.begin()									
			s.shutdown(1)
			s.close()
			return data
		except socket.error,exc:
			print "Error Connecting to Port " + str(port)
			return 0                                                

	def attack_service(self,interface_id,path,attack_file_full_path):
		f = open(attack_file_full_path,'rb')		
		s = self.get_socket(self.host,self.current_port)
		#attack_string = interface_id + " " +path + " HTTP/1.1 \r\nHOST: " + self.host + ":"+str(self.current_port)+" \r\n\r\n"
		#TODO: This is not the correct template as per spec. The above is the correct one. 
		attack_string = "RDSERVICE" + " " +path + " HTTP/1.1 \r\nHOST: " + self.host + ":"+str(self.current_port)+" \r\n\r\n"
		#print "*************************"
		#print attack_string
		#print "*************************"
		s.sendall(attack_string)
		l = f.read(1024)
		while (l):    
			s.sendall(l)
			l = f.read(1024)
		f.close()
		try:
			data = HTTPResponse(s)
			data.begin()
			if (data.status > 0):
				print TEST_CASE_RESULT_TEMPLATE % ("RD Service withstood the attack " + attack_file_full_path, TEST_CASE_RESULT_FAILURE)
		except:
			print TEST_CASE_RESULT_TEMPLATE % ("RD Service withstood the attack " + attack_file_full_path, TEST_CASE_RESULT_PASS)
		s.shutdown(1)
		s.close()
		# TODO: The data has to be parsed and RD service details should be obtained.
		

	
