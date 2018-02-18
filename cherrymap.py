import xml.etree.cElementTree as ET
from libnmap.parser import NmapParser
import os
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("-ah", "--allhosts", action="store_true",
                    help="add all hosts even when no open ports are detected")
parser.add_argument("-ap", "--allports", action="store_true",
                    help="add ports closed or filtered")
parser.add_argument("-a", "--all", action="store_true",
                    help="same as '-ah -ap'")
parser.add_argument("folder",
                    help="folder where nmap outputs are stored")
args = parser.parse_args()

path=args.folder+"/"
uid=1
root = ET.Element("cherrytree")

for filename in os.listdir(path):
	if not filename.endswith('.xml'): continue
	try:
		rep = NmapParser.parse_fromfile(path+filename)
	except:
		continue

	node = ET.SubElement(root, "node", custom_icon_id="0", foreground="", is_bold="False", name=filename.split(".")[0], prog_lang="custom-colors", readonly="False", tags="", unique_id=str(uid))
	uid=uid+1

	try:
		with open(path+filename.split(".")[0]+".nmap") as f: s = f.read()
		ET.SubElement(node, "rich_text").text=s
	except EnvironmentError:
		print "Nmap file not found it won't be added"

	for _host in rep.hosts:
		if (_host.is_up() and len(_host.services)>0) or args.allhosts or args.all:
			host = ET.SubElement(node, "node", foreground="", is_bold="False", name=_host.address, prog_lang="custom-colors", readonly="False", tags="", unique_id=str(uid))
			uid=uid+1
			fing = ET.SubElement(host, "rich_text")
			fp = str(_host.hostnames)+_host.os_fingerprint+"\n"
			if _host.os_fingerprinted:
				for os in _host.os_match_probabilities():
					fp = fp + os.name + "\n"
			fing.text=fp
			for  _service in _host.services:
				if _service.open() or args.allports or args.all:
					color=""
					if not _service.open():
						color="#ff0000"
					service = ET.SubElement(host, "node", foreground=color, is_bold="False", name=str(_service.port) + "/" + _service.protocol + " - " + _service.service, prog_lang="custom-colors", readonly="False", tags="", unique_id=str(uid))
					uid=uid+1
					ET.SubElement(service, "rich_text", style="italic", weight="heavy").text="Banner:\n"
					ET.SubElement(service, "rich_text").text=_service.banner+"\n\n\n"
					ET.SubElement(service, "rich_text", style="italic", weight="heavy").text="Scripts:\n"
					for scr in _service.scripts_results:
						ET.SubElement(service, "rich_text", weight="heavy").text=scr['id']+"\n"
						ET.SubElement(service, "rich_text").text=scr['output']+"\n"

tree = ET.ElementTree(root)
tree.write("cherrymap.ctd")
