from Framework.Host import Host


def test():
    host = Host(b'1234567890123456', ('127.0.0.1', 51234))
    host.send("test", "127.0.0.1", 12345)


if __name__ == '__main__':
    test()
