from Structures.PublicRingRow import PublicRingRow
from Structures.PrivateRingRow import PrivateRingRow
from Algorithms.FileUtil import FileUtil

print("Hello world")
print("Hello world")
print("Hello world")

f: FileUtil = FileUtil()
f.export_PEM("Hello world","PRIVATE_KEY")
print(f.import_PEM("PRIVATE_KEY"))
