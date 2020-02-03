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
parser.add_argument("-m", "--merge", action="store",
                    help="Merge the content into another CherryTree file. That file must be closed.")
parser.add_argument("file",
                    help="Nmap XML file to parse (relative path to current directory)")
args = parser.parse_args()

# Absolute path of the file
filename=os.path.abspath(args.file)

dest_file = args.merge

uid=1
root = ET.Element("cherrytree")

try:
    rep = NmapParser.parse_fromfile(filename)
except:
    print("Error while parsing file " + filename)

if dest_file == "":
    node = ET.SubElement(root, "node", custom_icon_id="0", foreground="", is_bold="False", name=os.path.basename(filename), prog_lang="custom-colors", readonly="False", tags="", unique_id=str(uid))
    uid=uid+1
else :
    # Parse destination file
    dest_tree_file = ET.parse(dest_file)
    dest_tree = dest_tree_file.getroot()
    
    # Find the last value of unique_id to properly set it on new items
    nodeList = [node for node in dest_tree.findall('.//node') ]
    lastNode = nodeList[-1]
    uid=int(lastNode.attrib['unique_id'])+1

    # Set the node as SubElement of the destionation file XML tree
    node = ET.SubElement(dest_tree, "node", custom_icon_id="0", foreground="", is_bold="False", name=os.path.basename(filename), prog_lang="custom-colors", readonly="False", tags="", unique_id=str(uid))

try:
    # Locate the .nmap file to parse it as the Tree Node content
    with open(filename.split(".")[0]+".nmap") as f: summary = f.read()
    ET.SubElement(node, "rich_text").text=summary
except EnvironmentError:
    print "Nmap file not found, the whole nmap output won't be added to document tree"

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
                service = ET.SubElement(host, "node", foreground=color, is_bold="False", name=str(_service.port) + " (" + _service.protocol.upper() + ") - " + _service.service, prog_lang="custom-colors", readonly="False", tags="", unique_id=str(uid))
                uid=uid+1
                ET.SubElement(service, "rich_text", style="italic", weight="heavy").text="Banner:\n"
                ET.SubElement(service, "rich_text").text=_service.banner+"\n\n\n"
                ET.SubElement(service, "rich_text", style="italic", weight="heavy").text="Scripts:\n"
                for scr in _service.scripts_results:
                    ET.SubElement(service, "rich_text", weight="heavy").text=scr['id']+"\n"
                    ET.SubElement(service, "rich_text").text=scr['output']+"\n"

if dest_file == "" : 
    tree = ET.ElementTree(root)
    tree.write(os.path.splitext(filename)[0] + ".ctd")
else :
    # Overwrite the destination file with the new XML tree 
    with open(dest_file, 'w') as f:
        f.write(ET.tostring(dest_tree))
