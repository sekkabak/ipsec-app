import threading


class Trigger:
    __subscribers: list

    def __init__(self):
        self.__subscribers = []

    def run(self, callback_data: list):
        for callback in self.__subscribers:
            thr = threading.Thread(target=callback, args=(callback_data,), kwargs={})
            thr.start()
            thr.is_alive()

    def subscribe(self, callback):
        self.__subscribers.append(callback)
