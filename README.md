# Cherrymap
Export nmap scans logs to cherrymap

Useful script to assist you during infrastructure assessments, importing to Cherrymap (https://www.giuspen.com/cherrytree/) results of Nmap scans.

```
usage: cherrymap.py [-h] [-ah] [-ap] [-a] folder

positional arguments:
  folder           folder where nmap outputs are stored

optional arguments:
  -h, --help       show this help message and exit
  -ah, --allhosts  add all hosts even when no open ports are detected
  -ap, --allports  add ports closed or filtered
  -a, --all        same as '-ah -ap'
```
