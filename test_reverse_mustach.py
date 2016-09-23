import pystache
import re
import unittest

from rest_stub import reverse_pystache, MustacheException



class TestReverseMNustache(unittest.TestCase):
    def test_no_pattern_1(self):
        ret = reverse_pystache('','')

    def test_no_pattern_2(self):
        ret = reverse_pystache('/aaa/ccc/xxx','/aaa/ccc/xxx')
        self.assertIsNone(ret)

    def test_no_pattern_2(self):
        ret = reverse_pystache('/aaa/ccc/xxx','/aaa/ccc/zzz')
        self.assertIsNone(ret)

    def test_2(self):
        template = '/uri/{{id}}/{{name}}'
        content = '/uri/1234/appelboom'

        ret = reverse_pystache(template, content)
        self.assertEqual(ret, {'name':'appelboom', 'id':'1234'})
    
    def test_3(self):
        template = '/uri/{{id}}/{{name}}'
        content = '/uri/appelboom'
        ret = reverse_pystache(template, content)

        self.assertIsNone(ret)

if __name__ == '__main__':
    unittest.main()