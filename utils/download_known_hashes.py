#!/usr/bin/python
import sys
import requests

directory = "https://www.4byte.directory/api/v1/signatures/?ordering=created_at&format=json"

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print "Download known hashes from https://www.4byte.directory/"
        print "Usage: python download_known_hashes.py known_hashes.py"
        exit(0)

    filename_output = sys.argv[1]

    hashes = 'knownHashes = {\n'
    downloading = True
    session = requests.Session()

    while downloading:

        print directory
        json = session.get(directory).json()

        for known_hash in json['results']:
            hashes += '    \'{}\': \'{}\',\n'.format(known_hash['hex_signature'], known_hash['text_signature'])

        directory = json['next']

        if directory is None:
            downloading = False

    hashes += '}\n'

    f = open(filename_output, 'wb')
    f.write(hashes)
    f.close()



