import time
import pandas as pd
import numpy as np

#the profiler object is meant to profile a single operation, then write its data to a file and delete
class profiler():
    int index
    int start_time
    int elapsed_time
    int bytes
    int data_rates[]
    int times[]

    #initialize all data to 0 in a new profile
    def __init__(self)
        self.index = 0
        self.start_time = 0
        self.elapsed_time = 0
        self.data_rates = np.zeros()

    #record the time the file operation starts
    def start_timer():
        start_time = time.time()

    #compute the time the file operation took and compute the data rate
    def stop_timer():
        elapsed_time = start_time - time.time()
        times[index] = elapsed_time
        data_rates[index] = bytes/elapsed_time
        index++

    def make_csv
