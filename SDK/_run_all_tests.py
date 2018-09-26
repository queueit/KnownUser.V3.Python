import unittest

suite = unittest.TestLoader().discover("")
unittest.TextTestRunner(verbosity=1).run(suite)