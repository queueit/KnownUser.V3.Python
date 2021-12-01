import sys
import unittest

suite = unittest.TestLoader().discover("")
result = unittest.TextTestRunner(verbosity=1).run(suite)

if result.wasSuccessful():
    sys.exit(0)
else:
    sys.exit(1)
