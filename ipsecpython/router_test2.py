from Router import Router


if __name__ == '__main__':
    a = Router('127.0.0.32', 10000, 10001)
    a.add_to_static_routes('127.0.0.16', '255.255.255.240') # network 1 
    a.add_to_static_routes('127.0.0.48', '255.255.255.240') # network 3
    a.start()