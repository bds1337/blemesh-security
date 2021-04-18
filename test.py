import unittest
import codecs
import meshsec as ms

class Tests(unittest.TestCase):
    def test_gen_salt(self):
        wanted = b'\xb7<\xef\xbdd\x1e\xf2\xeaY\x8c+n\xfbb\xf7\x9c'
        result = ms.gen_salt("test")
        self.assertEqual(result, wanted)
    
    def test_gen_k1(self):
        n = b"\x32\x16\xd1\x50\x98\x84\xb5\x33\x24\x85\x41\x79\x2b\x87\x7f\x98"
        salt = b"\x2b\xa1\x4f\xfa\x0d\xf8\x4a\x28\x31\x93\x8d\x57\xd2\x76\xca\xb4"
        T = b"\x5a\x09\xd6\x07\x97\xee\xb4\x47\x8a\xad\xa5\x9d\xb3\x35\x2a\x0d"
        wanted = b"\xf6\xed\x15\xa8\x93\x4a\xfb\xe7\xd8\x3e\x8d\xcb\x57\xfc\xf5\xd7"
        result = ms.gen_k1(n, salt, T)
        self.assertEqual(result, wanted)

    def test_gen_k4(self):
        n = b"\x32\x16\xd1\x50\x98\x84\xb5\x33\x24\x85\x41\x79\x2b\x87\x7f\x98"
        wanted = b'38'
        result = ms.gen_k4(n)
        self.assertEqual(result, wanted)

if __name__ == '__main__':
    unittest.main()