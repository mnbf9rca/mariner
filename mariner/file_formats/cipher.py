from dataclasses import dataclass
import numpy as np
import hashlib

@dataclass
class Keyring86:
	initial: int
	key: int
	index: int

# Key encoding provided by:
# https://github.com/cbiffle/catibo/blob/master/doc/cbddlp-ctb.adoc
	@classmethod
	def __init__(cls, seed: int, slicenum: int):
		initial = seed * 763612588 + 3634902051
		key = (int(slicenum * 504705229) + 3963439053) * int(initial)
		cls.initial = int(initial)
		cls.key = int(key)
		cls.index = 0
	
	@classmethod
	def Next(cls) -> bytes:
		k = int(cls.key >> int(8 * cls.index))
		cls.index += 1
		if cls.index & 3 == 0:
			cls.key = int(cls.key + cls.initial)
			cls.index = 0
		return k.to_bytes((k.bit_length() + 7) // 8, 'little')

	@classmethod
	def Read(cls, data: bytes) -> bytes:
		out = bytearray()
		for i in data:
			temp = cls.Next()
			out.extend([i^temp[0]])
		return bytes(out)
		
def cipher86(seed, slicenum, data):
	if seed == 0:
		return data
	kr = Keyring86(seed,slicenum)
	return kr.Read(data)


@dataclass
class KeyringFDG:
	initial: int
	key: int
	index: int

# Key encoding provided by:
# https://github.com/cbiffle/catibo/blob/master/doc/cbddlp-ctb.adoc
	@classmethod
	def __init__(cls, seed: int, slicenum: int):
		initial = seed - 499873475 ^ 629023793
		key = int(initial * 2184781565) * int(slicenum ^ 285989581)
		cls.initial = int(initial)
		cls.key = int(key)
		cls.index = 0
	
	@classmethod
	def Next(cls) -> bytes:
		k = int(cls.key >> int(8 * cls.index))
		cls.index += 1
		if cls.index & 3 == 0:
			cls.key = int(cls.key + cls.initial)
			cls.index = 0
		return k.to_bytes((k.bit_length() + 7) // 8, 'little')


	@classmethod
	def Read(cls, data: bytes) -> bytes:
		out = bytearray()
		for i in data:
			temp = cls.Next()
			out.extend([i^temp[0]])
		return bytes(out)
		
def cipherFDG(seed, slicenum, data):
	if seed == 0:
		return data
	kr = KeyringFDG(seed,slicenum)
	out = kr.Read(data)
	return 
		
def computeSHA256Hash(input: bytes):
	output = hashlib.sha256()
	output.update(input)
	return output.digest()

# https://github.com/sn4k3/UVtools/blob/2625c13cc3179a55865e5594180050258ab60a95/UVtools.Core/Extensions/CryptExtensions.cs#L59
def xorCipher(text: bytes, key: bytes):
	output = bytearray(len(text))
	for i in range(len(text)):
		output[i] = (text[i] ^ key[i % len(key)])
	return output
