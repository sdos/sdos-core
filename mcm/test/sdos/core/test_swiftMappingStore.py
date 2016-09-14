from unittest import TestCase
from MappingPersistence import SwiftMappingStore
import io

from SwiftBackend import SwiftBackend


class TestSwiftMappingStore(TestCase):
	def setUp(self):
		self.sc = SwiftBackend(user="test:tester", key="testing")
		self.sc.create_container_if_not_exists(container="TEST")
		self.ms = SwiftMappingStore(containerNameSdosMgmt="TEST", swiftBackend=self.sc)

	def test_swift_Mapping(self):
		by_test = io.BytesIO()
		by_read = io.BytesIO()
		s = b"here we go!"
		by_test.write(s)


		self.ms.writeMapping(by_test)
		by_read = self.ms.readMapping()

		self.assertEqual(by_test.getvalue(), by_read.getvalue())
