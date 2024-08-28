from StringIO import StringIO

class NASStringIO(StringIO):

    def __enter__(self):
        if self.closed:
          raise ValueError("I/O operation on closed file")

        return self

    def __exit__(self, exc, value, tb):
        self.close()

