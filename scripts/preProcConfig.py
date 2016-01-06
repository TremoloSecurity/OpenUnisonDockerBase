#!/usr/bin/python

import sys
import os

fileToCheck = sys.argv[1];
fileToWrite = sys.argv[2];

print "File to process : " + fileToCheck
print "Output Path : " + fileToWrite

f = open(fileToCheck,'r')
txt = f.read()
outtxt = ''
start = txt.find('#[')
end = 0

while start > -1:
    outtxt += txt[end:start]
    start += 2
    end = txt.find(']',start)
    envVarName = txt[start:end]
    outtxt += os.environ[envVarName]
    start = txt.find('#[',end)
    end += 1

if end == 0:
    outtxt = txt
else:
    outtxt += txt[end:]

f.close()
f = open(fileToWrite,'w')
f.write(outtxt)
f.close()
