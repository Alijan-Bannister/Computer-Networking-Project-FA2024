import time
import csv

#the profiler object is meant to profile a single operation, then write its data to a file and delete
class profiler():
    start_time = 0
    elapsed_time = 0
    bytes = 0
    data_rates = []
    times = []

    #record the time the file operation starts
    def start_timer(self):
        self.start_time = time.time()

    #compute the time the file operation took and the data rate
    def stop_timer(self):
        self.elapsed_time = self.start_time - time.time()
        self.times.append(self.elapsed_time)
        self.data_rates.append(self.bytes/self.elapsed_time)
        
    def record_bytes(self, new_bytes):
        self.bytes += new_bytes
        
    def reset(self):
        self.start_time = 0
        self.elapsed_time = 0
        self.bytes = 0
        self.data_rates.clear()
        self.times.clear()
        
    def make_csv(self):
        csvdata = [self.times, self.data_rates]

        with open ('output.csv', mode = 'w', newline = '') as file:
            writer = csv.writer(file)
            writer.writerows(csvdata)
        self.reset()
