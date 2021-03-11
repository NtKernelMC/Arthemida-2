##############################################################################
#
#  PROJECT:     Multi Theft Auto v1.0
#  LICENSE:     See LICENSE in the top level directory
#  FILE:        utils/pull_pootle_catalogs.py
#  PURPOSE:     Pull translation files from a Pootle web server into a directory
#  DEVELOPERS:  Dan Chowdhury <>
#
#  Multi Theft Auto is available from http://www.multitheftauto.com/
#
##############################################################################

import os
import shutil
import urllib2
import urlparse
import time
import sys
import socket
import polib
import re
from optparse import OptionParser

# urlopen with which returns empty string on error
def myurlopen(url,urltimeout):
    content = ""
    try:
        header = {"pragma-directive" : "no-cache","PRAGMA" : "NO-CACHE","CACHE-CONTROL" : "NO-CACHE"}
        req = urllib2.Request(url, headers=header)
        u = urllib2.urlopen(req, timeout = urltimeout)
        content = u.read()
    except urllib2.URLError as e:
        print type(e)
    except socket.timeout as e:
        print type(e)
    return content

# urlopen with over complex handling of connection issues
def myurlopenDeluxe(url,urltimeout,attempts):
    print ( "Trying '%s'"%(url) )
    for x in range(0, attempts):
        # Get file first
        content = myurlopen(url,urltimeout)
        if ( len(content) > 0 ):
            print ( "content size %d"%(len(content)) )
            for y in range(0, attempts):
                # Get file second
                content2 = myurlopen(url,urltimeout)
                if ( len(content2) > 0 ):
                    print ( "content2 size %d"%(len(content2)) )
                    # Check both downloads got the same result
                    if ( content == content2 ):
                        print ( "Download success" )
                        return content
                    break;
                # try again
                time.sleep(0.25)
            print ( "Downloads did no match" )
        else:
            print ( "Download failed" )
        # try again
        time.sleep(0.5)

    # It's all gone pear shaped
    print ( "ERROR: Download total failure" )
    sys.exit(1)


parser = OptionParser()
parser.add_option("-u", "--url", dest="url",
            help="Pootle homepage URL", default="http://translate.mtasa.com/")
parser.add_option("-o", "--output", dest="output",
            help="Output directory", default="../Shared/data/MTA San Andreas/MTA/locale")
parser.add_option("-p", "--project", dest="project",
            help="Internal name of the pootle project", default="client")
parser.add_option("-G", "--gnu",action="store_true", dest="gnu", default=False,
            help="Whether the project is a GNU directory layout")
parser.add_option("-L", "--languages",dest="languages", 
            help="A comma delimited list of languages to pull from Pootle", default='de,fr')
parser.add_option("-r", "--rmdir",action="store_true", dest="rmdir", default=False,
            help="Clear the output directory before starting")
parser.add_option("-t", "--timeout",type="float", dest="urltimeout", default=30,
            help="HTTP fetch timeout")
parser.add_option("-i", "--index",type="int", dest="langindex", default=-1,
            help="If set, only do one language. Returns 2 if index out of range")
parser.add_option("-a", "--attempts",type="int", dest="attempts", default=3,
            help="Number of download retry attempts before giving up")
parser.add_option("-e", "--excludeusers", dest="excludeusers", default="",
            help="A comma delimited list of Pootle usernames to exclude from the Translators: header")

(options, args) = parser.parse_args()

# e.g.:
# http://translate.mtasa.com/export/installer/hr.po
# http://translate.mtasa.com/download/hr/installer/hr.po
#
# http://translate.mtasa.com/export/client/nl/client.po
# http://translate.mtasa.com/download/nl/client/client.po

if options.rmdir:
    # Clear our output directory first
    if os.path.exists(options.output):
        shutil.rmtree(options.output)
    print ( "Cleared output directory: '%s'"%(options.output) )

# Let's split our option strings into Python lists
langlist = (options.languages).replace(" ","").split(",")
excludeUserList = (options.excludeusers).replace(" ","").split(",")

# Select one language if required
if options.langindex > -1:
    if options.langindex >= len(langlist):
        print ( "Index out of range" )
        sys.exit(2)
    langlist = [langlist[options.langindex]]

# Loop over the list
for lang in (langlist):
    # Let's create our full Pootle export URL depending on whether we're GNU or not
    url = ""
    alturl = ""
    output = ""
    if options.gnu:
        url = urlparse.urljoin(options.url, "export/%s/%s.po"%(options.project,lang))
        alturl = urlparse.urljoin(options.url, "download/%s/%s/%s.po"%(lang,options.project,lang))
        output = os.path.join(options.output,"%s.po"%(lang))
    else:
        url = urlparse.urljoin(options.url, "export/%s/%s/%s.po"%(options.project,lang,options.project))
        alturl = urlparse.urljoin(options.url, "download/%s/%s/%s.po"%(lang,options.project,options.project))
        output = os.path.join(options.output,"%s/%s.po"%(lang,options.project))

    # Read from alt url first (try to flush pootle cache)
    content = myurlopenDeluxe(alturl,options.urltimeout,options.attempts)
    content = myurlopenDeluxe(url,options.urltimeout,options.attempts)

    path,tail = os.path.split(output)
    if ( not os.path.exists(path) ):
        os.makedirs(path)
    
    localFile = open(output, 'w')
    localFile.write(content)
    localFile.close()
    print ( "Read '%s' and written to '%s'"%(url,output) )

    # Tidy translators list
    po = polib.pofile(output)
    translatorList = po.metadata["Translators"].split('; ')
    p = re.compile('(.*) "(.*)" (.*)')
    newTranslatorList = []
    for translator in (translatorList):
        m = p.match(translator)
        if not m:
            accountName = translator
        else:
            firstName = m.group(1)
            accountName = m.group(2)
            secondName = m.group(3)
            if firstName != secondName:
                translator = firstName+" "+secondName
            else:
                translator = firstName

        # Remove admins from credits
        if not accountName in excludeUserList:
            newTranslatorList.append(translator)

    po.metadata["Translators"] = "; ".join(newTranslatorList);
    po.save(output)
