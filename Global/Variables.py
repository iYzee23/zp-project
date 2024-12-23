from Structures.PrivateRing import PrivateRing
from Structures.PublicRing import PublicRing
from Algorithms.RSA import RSA

users = [
    ["vuletic123", "Vuletic", "vuletic@etf.rs", "AES128"],
    ["vukasovic123", "Vukasovic", "vukasovic@etf.rs", "AES128"],
    ["milakovic123", "Milakovic", "milakovic@etf.rs", "AES128"],
    ["radaljac123", "Radaljac", "radaljac@etf.rs", "AES128"],
    ["nevajda123", "Nevajda", "nevajda@etf.rs", "DES3"],
    ["pesic123", "Pesic", "pesic@etf.rs", "DES3"]
]

private_rings = {}
t = [PrivateRing(), PrivateRing(), PrivateRing(), PrivateRing(), PrivateRing(), PrivateRing()]

public_rings = {}
p = [PublicRing(), PublicRing(), PublicRing(), PublicRing(), PublicRing(), PublicRing()]

pp_keys = []
for i in range(6):
    pp_keys.append(RSA.import_keys(i + 1))

for i in range(6):
    t[i].add_row(pp_keys[i][0], pp_keys[i][1], users[i][0], users[i][1], users[i][2], users[i][3])
    for j in range(6):
        if i == j:
            continue
        p[i].add_row(pp_keys[j][0], users[j][1], users[j][2])
    private_rings[users[i][1] + "###" + users[i][2]] = t[i]
    public_rings[users[i][1] + "###" + users[i][2]] = p[i]
