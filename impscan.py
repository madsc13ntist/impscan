#!/usr/bin/env python

__version__    = "0.0.1"
__date__       = "08.29.2014"
__author__     = "Joseph Zeranski"
__maintainer__ = "Joseph Zeranski"
__email__      = "madsc13ntist@gmail.com"
__copyright__  = "Copyright 2014, " + __author__
__license__    = "MIT"
__status__     = "Prototype"
__credits__    = [""]
__description__= "return import hash matches present in a malware directory/repository.  takes a file or imphash."
__build__      = ""

####################### MIT License #######################
# Copyright (c) 2014 Joseph Zeranski
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
# The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
###########################################################

### Import Modules
import os
import pefile    #Requires pefile 2.10.139 (or newer)
import hashlib
import optparse

# You can add some additional/default dirs to scan through.
DIRS_TO_SCAN = []  #"/malware/report", "/malware/zoo"]

### Define Functions
def imphash(filepath):
    """
    Return the import hash of an executable
    """
    try:
        pe = pefile.PE(filepath)
        return pe.get_imphash()
    except:
        return False

def files_in(directory, escape_spaces=False, escape_char='\\'):
    """
    Walks through a directory recursively (like unix 'find') returns a list of filepaths.
    """
    #import os
    file_list = []
    for root, subFolders, files in os.walk(directory):
         for filename in files:
                filePath = os.path.join(root, filename)
                if escape_spaces:
                    filePath = filePath.replace(' ', escape_char+' ')
                file_list.append(filePath)
                #print(filePath)
    return file_list


### If the script is being executed (not imported).
if __name__ == "__main__":
    if not __build__:
        __build__ = hashlib.md5(open(__file__, 'rb').read()).hexdigest()
    opt_parser = optparse.OptionParser()
    opt_parser.usage  = "%prog [options] FILE(S) or HASHE(S)\n"

    #''' Additional formatting for Meta-data ''''''''''''''''''
    opt_parser.usage += "version " + str(__version__) + ", build " + __build__ + "\n"
    if __description__ not in ["", [""], None, False]:
        opt_parser.usage += __description__ + "\n"
    opt_parser.usage += "Copyright (c) 2014 " + __author__ + " <" + __email__ + ">"
    if __credits__ not in ["", [""], None, False]:
        opt_parser.usage += "\nThanks go out to "
        if isinstance(__credits__, str):
            opt_parser.usage += __credits__ + "."
        elif isinstance(__credits__, list):
            if len(__credits__) == 1:
                opt_parser.usage += __credits__[0] + "."
            else:
                opt_parser.usage += ', '.join(__credits__[:-1]) + " and " + __credits__[-1] + "."
    #'''''''''''''''''''''''''''''''''''''''''''''''''''''''''''
    opt_parser.add_option("-d",
                          dest    = "dir",
                          action  = "append",
                          default = [],
                          help    = "Dir to scan for matching files with matching imphashes.")
    (options, args) = opt_parser.parse_args()

    # Do things with your options and args.
    if not args:
        opt_parser.print_help()	# Print usage info
        exit(1)

    if len(options.dir) < 1 and len(DIRS_TO_SCAN) < 1:
        options.dir.append('.')
    else:
        for d in DIRS_TO_SCAN:
            options.dir.append(d)
    options.dir = [ os.path.abspath(x) for x in options.dir ]
    ### create a list of filepaths that will have their imphash collected.
    files_to_process = []
    for d in options.dir:
        for p in files_in(d):
            files_to_process.append(p)

    for arg in args:
        if os.path.isdir(arg):
            for p in files_in(arg):
                files_to_process.append(p)
        elif os.path.isfile(arg):
            files_to_process.append(arg)
    files_to_process.sort()

    hashes = {}

    for filepath in files_to_process:
        hash = imphash(filepath)
        if hash:
            if hash not in hashes:
                hashes[hash] = [filepath]
            else:
                hashes[hash].append(filepath)

    for arg in args:
        hash = ""
        if os.path.isfile(arg):
            hash = imphash(arg)
            if hash in hashes:
                for filepath in sorted(hashes[hash]):
                    if os.path.abspath(filepath) != os.path.abspath(arg):
                        print("%s %s" % (hash, os.path.abspath(filepath)))
        else:
            if arg in hashes:
                for filepath in sorted(hashes[arg]):
                    print("%s %s" % (arg, os.path.abspath(filepath)))
