from enum import Enum
import time
import sys

#take a STRING from the server
rcvd = sys.stdin()

class switch(Enum):
    time = "time"        #the server sends the stop or start time to the profiler
    data = "data"        #the server sends a packet size
    confirm = "confirm"  #the server tests to see if the profiler is running and connected

#use ' | ' to delineate the command and the data, same as the client-server connection
rcvd = rcvd.split(' | ')
cmd = rcvd[0]
data = rcvd[1]

if(cmd = "time"):
    if (startTime == 0):
        startTime = data
    else:
        endTime = data
    
if(cmd = "confirm")
    sys.stdout.write("profiler running")
