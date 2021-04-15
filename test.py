import unittest

import netgen

class TestSum(unittest.TestCase):
    def test_gen_salt(self):
        """
        s1(test) = b73cefbd641ef2ea598c2b6efb62f79c
        """
        wanted = b"b73cefbd641ef2ea598c2b6efb62f79c"
        result = netgen.gen_salt("test")
        self.assertEqual(result, wanted)

if __name__ == '__main__':
    unittest.main()