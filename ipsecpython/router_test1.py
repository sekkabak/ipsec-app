from Router import Router


if __name__ == '__main__':
    b = Router('127.0.0.16', 10000, 10001)
    b.add_to_static_routes('127.0.0.17', '255.255.255.255') # host 1
    b.add_to_static_routes('127.0.0.32', '255.255.255.240') # network 2
    b.add_to_static_routes('127.0.0.48', '255.255.255.240', '127.0.0.32') # network 3
    b.start()