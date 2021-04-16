import unittest

import meshsec as ms

class Tests(unittest.TestCase):
    def test_gen_salt(self):
        #wanted = b"b73cefbd641ef2ea598c2b6efb62f79c"
        wanted = b'\xb7<\xef\xbdd\x1e\xf2\xeaY\x8c+n\xfbb\xf7\x9c'
        result = ms.gen_salt("test")
        self.assertEqual(result, wanted)

if __name__ == '__main__':
    unittest.main()