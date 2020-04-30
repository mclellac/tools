#!/usr/bin/env python
import re
import random
import urllib.request

url1 = input("Enter the URL ")
u = chr(random.randint(97,122))
url2 = url1+u
http_r = urllib.request.urlopen(url2)

content=http_r.read()
flag = 0
i = 0
list1 = []
a_tag = "<*address>"
file_text = open("result.txt",'a')

while flag == 0:
    if http_r.code == 404:
        file_text.write("--------------")
        file_text.write(url1)
        file_text.write("--------------n")

        file_text.write(content)

        for match in re.finditer(a_tag, content):
            i = i+1
            s = match.start()
            e = match.end()
            list1.append(s)
            list1.append(e)

        if (i > 0):
            print("Coding is not good")

        if len(list1) > 0:
            a = list1[1]
            b = list1[2]
            print(content[a:b])
        else:
            print("error handling seems ok")
            flag = 1
    elif http_r.code == 200:
        print("Web page is using custom Error page")
        break
