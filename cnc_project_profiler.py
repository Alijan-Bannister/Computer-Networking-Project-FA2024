import time
import csv
import numpy as np

#the profiler object is meant to profile a single operation, then write its data to a file and delete
class profiler():
    start_time = 0
    elapsed_time = 0
    bytes = 0
    data_rates = []
    times = []

    #record the time the file operation starts
    def start_timer(self):
        start_time = time.time()

    #compute the time the file operation took and the data rate
    def stop_timer(self):
        elapsed_time = start_time - time.time()
        times.append(elapsed_time)
        data_rates.append(bytes/elapsed_time)
        
    def record_bytes(bytes, self)
    self.bytes = bytes
    
    def make_csv(self):
        csvdata = [times, data_rates]

        with open ('output.csv', mode = 'w', newline = '') as file:
            writer = csv.writer(file)
            writer.writerows(csvdata)
