def convert_to_seconds(time_str):
    """
    Convert the given time string to seconds based on its unit.
    Supports 'ms' for milliseconds, 's' for seconds, and 'µs' for microseconds.
    """
    # Check if time_str ends with 'ms' (milliseconds)
    if time_str.endswith('ms'):
        return float(time_str[:-2]) / 1000  # Convert milliseconds to seconds
    # Check if time_str ends with 's' (seconds)
    elif time_str.endswith('s') and not time_str.endswith('µs'):  # Ensure it's not 'µs'
        return float(time_str[:-1])  # It's already in seconds
    # Check if time_str ends with 'µs' (microseconds)
    elif time_str.endswith('µs'):
        return float(time_str[:-2]) / 1000000  # Convert microseconds to seconds
    else:
        raise ValueError("Invalid unit. Please use 'ms', 's', or 'µs'.")

def sum_time_inputs(time_list):
    """
    Sum a list of time values in different units and return the total time in seconds.
    """
    total_seconds = 0
    for time_input in time_list:
        total_seconds += convert_to_seconds(time_input)
    return total_seconds

# Example usage:
time_list = ['86.142038ms', '77.245548821s', '1.799438636s', '125.240944682s']

# Sum the times in the list and get the total in seconds
total_time = sum_time_inputs(time_list)

# Output the total time in seconds
print(f"Total time in seconds: {total_time:.6f}")
