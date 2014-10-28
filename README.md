impscan
=======

return import hash matches present in a malware directory/repository.  (takes a file or imphash).

~~~~
Usage: impscan.py [options] FILE(S) or HASHE(S)
version 0.0.1, build 77fafcd61ac42503bac52d7b1e7e6092
return import hash matches present in a malware directory/repository.  takes a file or imphash.
Copyright (c) 2014 Joseph Zeranski <madsc13ntist@gmail.com>

Options:
  -h, --help  show this help message and exit
  -d DIR      Dir to scan for matching files with matching imphashes.
~~~~

Example Usage 
=====
~~~~
$ ./impscan.py f7b824bdc1f89763a2dee17f68c0aa9f -d /malware/report/2014/07 -d /malware/report/2014/09
f7b824bdc1f89763a2dee17f68c0aa9f /malware/report/2014/07/20140731-01/malware/8d248e6d41f8954edc33f98ac38249a2cc94fd3dfeff7bbe64c33c3fed78e0ec
f7b824bdc1f89763a2dee17f68c0aa9f /malware/report/2014/09/20140911-01/malware/rasauto.dll
f7b824bdc1f89763a2dee17f68c0aa9f /malware/report/2014/09/20140912-01/malware/STMP.dll
f7b824bdc1f89763a2dee17f68c0aa9f /malware/report/2014/09/20140912-02/malware/STMP.dll

$ ./impscan.py -d /malware/report /malware/report/2014/09/20140912-02/malware/STMP.dll
f7b824bdc1f89763a2dee17f68c0aa9f /malware/report/2014/07/20140731-01/malware/8d248e6d41f8954edc33f98ac38249a2cc94fd3dfeff7bbe64c33c3fed78e0ec
f7b824bdc1f89763a2dee17f68c0aa9f /malware/report/2014/09/20140911-01/malware/rasauto.dll
f7b824bdc1f89763a2dee17f68c0aa9f /malware/report/2014/09/20140912-01/malware/STMP.dll
~~~~
