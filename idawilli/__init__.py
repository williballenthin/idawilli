def align(value, alignment=0x1000):
    if value % alignment == 0:
        return value
    return value + (alignment - (value % alignment))