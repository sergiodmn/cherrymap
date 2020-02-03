# Cherrymap
Import Nmap scans to Cherrytree

Useful script to assist you during infrastructure assessments, importing to Cherrytree (https://www.giuspen.com/cherrytree/) results of Nmap scans.

Note that both XML and .nmap files have to be present in the same folder. We recommend using the option `-oA file2save` when doing the scan. 

In case of merging the data into another CherryTree file (`-m` option), the utility will insert it as last node, with the filename as node name. 

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

![alt text](https://github.com/sergiodmn/cherrymap/blob/master/example/example1.png "Example 1")
![alt text](https://github.com/sergiodmn/cherrymap/blob/master/example/example2.png "Example 2")
