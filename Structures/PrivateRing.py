from Structures.PrivateRingRow import PrivateRingRow


class PrivateRing:
    def __init__(self):
        self.ring = {}

    def add_row(self, public_key, private_key, password, name, mail, algorithm):
        row = PrivateRingRow(public_key, private_key, password, name, mail, algorithm)
        self.ring[row.key_id] = row

    def get_row(self, key_id):
        return self.ring.get(key_id)

    def get_rows(self):
        return self.ring

    def __str__(self):
        return "\n".join(str(row) for row in self.ring.values())
