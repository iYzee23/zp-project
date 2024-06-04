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

"""
t1 = PrivateRing()
t1.add_row(pu1, pr1, "nevajda123", "Nevajda", "nevajda@etf.rs", "AES128")
t1.add_row(pu2, pr2, "nevajda123", "Nevajda", "nevajda@etf.rs", "DES3")
private_rings["Nevajda###nevajda@etf.rs"] = t1

t2 = PrivateRing()
t2.add_row(pu3, pr3, "pesic123", "Pesic", "pesic@etf.rs", "DES3")
t2.add_row(pu4, pr4, "pesic123", "Pesic", "pesic@etf.rs", "AES128")
private_rings["Pesic###pesic@etf.rs"] = t2

p1 = PublicRing()
p1.add_row(pu3, "Pesic", "pesic@etf.rs")
p1.add_row(pu4, "Pesic", "pesic@etf.rs")
public_rings["Nevajda###nevajda@etf.rs"] = p1

p2 = PublicRing()
p2.add_row(pu1, "Nevajda", "nevajda@etf.rs")
p2.add_row(pu2, "Nevajda", "nevajda@etf.rs")
public_rings["Pesic###pesic@etf.rs"] = p2
"""
