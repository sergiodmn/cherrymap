# Cherrymap
Import Nmap scans to Cherrytree

Useful script to assist you during infrastructure assessments, importing to Cherrytree (https://www.giuspen.com/cherrytree/) results of Nmap scans.

Note that both XML and .nmap files have to be present in the same folder. We recommend using the option `-oA file2save` when doing the scan. 


## Merging options

This utility can merge the nmap scan inside another CherryTree file. **This file must be a non-protected XML file, otherwise ths utility won't work !**. 
In case of merging the data into another CherryTree file (`-m` option), the utility will insert it as last node, with the filename as node name. 

You can convert any other format by opening it in CherryTree, then clicking on `Export` > `Export to CherrtyTree document` and select `XML, Not protected (.ctd)`.

## Requirements

 - `python3-libnmap`

## Usage

```
usage: cherrymap.py [-h] [-ah] [-ap] [-a] [-m dest_file] file

mandatory arguments:
  file             Nmap XML file to parse into cherry tree

optional arguments:
  -h, --help       show this help message and exit
  -ah, --allhosts  add all hosts even when no open ports are detected
  -ap, --allports  add ports closed or filtered
  -a, --all        same as '-ah -ap'
  -m, --merge      Specify a CherryTree destination file in which to write the contents
```

## Examples

![alt text](https://github.com/3isenHeiM/cherrymap/blob/master/example/example1.png "Example 1")
![alt text](https://github.com/3isenHeiM/cherrymap/blob/master/example/example2.png "Example 2")

![alt text](https://github.com/3isenHeiM/cherrymap/blob/master/example/example3.png "Example 3 : Merging into existing file")
