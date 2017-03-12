import os.path
import hashlib
import time
import sys

file = sys.argv[1]

class Stopwatch:
    def __init__(self):
        self.start_time = 0

    def start(self):
        self.start_time = int(round(time.time() * 1000))

    def stop(self):
        return int(round(time.time() * 1000)) - self.start_time


def get_file_hash_time(file, algorithm):
    """
    Hashes file and returns its hash
    :param file: file to be hashed
    :param algorithm: algorithm used for hashing
    :return: hash of the file or None when file does not exists or None when wrong algorithm is used
    """
    if not os.path.isfile(file):
        return None

    if algorithm == 'sha256':
        hash_function = hashlib.sha256()
    elif algorithm == 'sha1':
        hash_function = hashlib.sha1()
    elif algorithm == 'md5':
        hash_function = hashlib.md5()
    elif algorithm == 'sha512':
        hash_function = hashlib.sha512()
    else:
        return None

    file_reader = open(file, 'rb')
    time_reading = 0
    time_hashing = 0
    stopwatch = Stopwatch()
    while True:
        print('.', end='', flush = True)
        stopwatch.start()
        file_bytes = file_reader.read(32 * 1024 * 1024)
        time_reading += stopwatch.stop()
        if not file_bytes:
            break
        stopwatch.start()
        hash_function.update(file_bytes)
        time_hashing += stopwatch.stop()
    del file_bytes
    file_reader.close()

    stopwatch.start()
    print('X')
    file_hash = hash_function.hexdigest()
    time_hashing += stopwatch.stop()

    print(algorithm + ': ' + file_hash)
    print('Reading: %d' % time_reading)
    print('Hashing: %d' % time_hashing)
    print('Total:   %d' % (time_hashing + time_reading))
    return [algorithm, time_reading, time_hashing, time_reading + time_hashing]

get_file_hash_time(file, 'md5')
get_file_hash_time(file, 'sha1')
get_file_hash_time(file, 'sha256')
get_file_hash_time(file, 'sha512')
