class Options:
    def __init__(self, encryption, authentication, compression, radix64, algorithm):
        self.encryption = encryption
        self.authentication = authentication
        self.compression = compression
        self.radix64 = radix64
        self.algorithm = algorithm

    def __str__(self):
        str_encryption = f"E[{self.encryption}]\n"
        str_authentication = f"A[{self.authentication}]\n"
        str_compression = f"C[{self.compression}]\n"
        str_radix64 = f"R[{self.radix64}]\n"
        str_algorithm = f"Algorithm[{self.algorithm}]\n"
        str_delimiter = f"#####\n"
        return str_encryption + str_authentication + str_compression + str_radix64 + str_algorithm + str_delimiter

    @staticmethod
    def create_options_object(options_string):
        lines = options_string.split('\n')
        if len(lines) != 6:
            raise ValueError("Invalid options")
        encryption = lines[0].split('[')[1][:-1]
        authentication = lines[1].split('[')[1][:-1]
        compression = lines[2].split('[')[1][:-1]
        radix64 = lines[3].split('[')[1][:-1]
        algorithm = lines[4].split('[')[1][:-1]

        return Options(encryption, authentication, compression, radix64, algorithm)
