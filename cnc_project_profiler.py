import csv
import time

# the profiler object is meant to profile a single operation, then write its data to a file and delete
class profiler():
  start_time: float = 0
  elapsed_time: float = 0
  bytes: int = 0
  data_rates: list[float] = []
  times: list[float] = []


  # record the time the file operation starts
  def start_timer(self) -> None:
    self.start_time = time.time()


  # compute the time the file operation took and the data rate
  def stop_timer(self) -> None:
    self.elapsed_time = time.time() - self.start_time
    self.times.append(self.elapsed_time)
    self.data_rates.append(self.bytes/self.elapsed_time)


  # records the total number of bytes in the upload/download
  def record_bytes(self, new_bytes) -> None:
    self.bytes += new_bytes / 1000000


  # reset the instance variables
  def reset(self) -> None:
    self.start_time = 0
    self.elapsed_time = 0
    self.bytes = 0
    self.data_rates.clear()
    self.times.clear()


  # create a csv with all the data in it
  def make_csv(self) -> None:
    csvdata: list[list[float]] = [self.times, self.data_rates]

    with open('CNC_Project_Data/output.csv', mode='w', newline='') as file:
      writer = csv.writer(file)
      writer.writerows(csvdata)
    self.reset()
