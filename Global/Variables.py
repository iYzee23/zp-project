from Structures.PrivateRing import PrivateRing
from Structures.PublicRing import PublicRing
from Algorithms.RSA import RSA

(pu1, pr1) = RSA.generate_keys(1024)
(pu2, pr2) = RSA.generate_keys(2048)
(pu3, pr3) = RSA.generate_keys(1024)
(pu4, pr4) = RSA.generate_keys(2048)

private_rings = {}

t1 = PrivateRing()
t1.add_row(pu1, pr1, "nevajda123", "Nevajda", "nevajda@etf.rs", "AES128")
t1.add_row(pu2, pr2, "nevajda123", "Nevajda", "nevajda@etf.rs", "DES3")
private_rings["Nevajda###nevajda@etf.rs"] = t1

t2 = PrivateRing()
t2.add_row(pu3, pr3, "pesic123", "Pesic", "pesic@etf.rs", "DES3")
t2.add_row(pu4, pr4, "pesic123", "Pesic", "pesic@etf.rs", "AES128")
private_rings["Pesic###pesic@etf.rs"] = t2

public_rings = {}

p1 = PublicRing()
p1.add_row(pu3, "Pesic", "pesic@etf.rs")
p1.add_row(pu4, "Pesic", "pesic@etf.rs")
public_rings["Nevajda###nevajda@etf.rs"] = p1

p2 = PublicRing()
p2.add_row(pu1, "Nevajda", "nevajda@etf.rs")
p2.add_row(pu2, "Nevajda", "nevajda@etf.rs")
public_rings["Pesic###pesic@etf.rs"] = p2
