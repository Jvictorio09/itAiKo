from datetime import timedelta

def dt_range(start, end, step: timedelta):
    while start < end:
        yield start
        start += step
