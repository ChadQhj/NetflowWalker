#!/usr/bin/python

import urllib
import urllib2
import re

html = ".html"
url = "http://alexa.chinaz.com/Country/index_CN" + html;
page = "http://alexa.chinaz.com/Country/index_CN_"

max_page = 20
cur_page = 0

with open("./user_white_domain_chinaz.txt","w") as f:
    f.write("#Reference: " + url + "\n")
    while cur_page < max_page:
        cur_page += 1
        
        if cur_page <= 1:
            next_page = url
        else:
            next_page = page + str(cur_page) + html
        
        print next_page
        
        req = urllib2.Request(next_page)
        
        try:
            resp = urllib2.urlopen(req)
            content = resp.read().decode('utf-8')
            pattern = re.compile('<div class="righttxt"><h3><a href="http://alexa.chinaz.com/(.*?)>(.*?)</a>')
            item = re.findall(pattern,content)
            print len(item)
            for it in item:
                print it[1]
                f.write(it[1]+'\n')
        except urllib2.URLError,e:
            if hasattr(e,"code"):
                print e.code
            if hasattr(e,"reason"):
                print e.reason
                
        else:
            print "ok===================="

    cur_page = 0
    max_page = 200
    url = "http://top.chinaz.com/hangye/index" + html
    page = "http://top.chinaz.com/hangye/index_"
    f.write("#Reference: " + url + "\n")
    while cur_page < max_page:
        cur_page += 1
        
        if cur_page <= 1:
            next_page = url
        else:
            next_page = page + str(cur_page) + html
        
        print next_page
        
        req = urllib2.Request(next_page)
        
        try:
            resp = urllib2.urlopen(req)
            content = resp.read()
            pattern = re.compile('<h3 class="rightTxtHead"><a href=(.*?)</a><span class="col-gray">(.*?)</span></h3>')
            item = re.findall(pattern,content)
            print len(item)
            for it in item:
                print it[1]
                f.write(it[1]+'\n')
        except urllib2.URLError,e:
            if hasattr(e,"code"):
                print e.code
            if hasattr(e,"reason"):
                print e.reason
                
        else:
            print "ok===================="
    
    f.close()
    
    
    

