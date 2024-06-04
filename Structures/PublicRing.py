from Structures.PublicRingRow import PublicRingRow


class PublicRing:
    def __init__(self):
        self.ring = {}

    def add_row(self, public_key, name, mail):
        row = PublicRingRow(public_key, name, mail)
        self.ring[row.key_id] = row

    def get_row(self, key_id):
        return self.ring.get(key_id)

    def get_rows(self):
        return self.ring

    def __str__(self):
        return "\n".join(str(row) for row in self.ring.values())
