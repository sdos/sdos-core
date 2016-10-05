from unittest import TestCase
from MappingPersistence import LocalFileMappingStore
import os, io


class TestLocalFileMappingStore(TestCase):

	def setUp(self):
		self.ms = LocalFileMappingStore()
		self.ms.fileName = "/tmp/sdosmappingtest"
		if os.path.isdir(self.ms.fileName):
			self.fail()
		if os.path.isfile(self.ms.fileName):
			os.remove(self.ms.fileName)



	def test_read_and_write_simple_Mapping(self):
		by_test = io.BytesIO()
		by_read = io.BytesIO()
		s = b"here we go!"
		by_test.write(s)


		self.ms.writeMapping(by_test)
		by_read = self.ms.readMapping()

		self.assertEqual(by_test.getvalue(), by_read.getvalue())


