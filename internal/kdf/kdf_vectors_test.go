package kdf

// Test vectors generated with Python cryptography PBKDF2HMAC(SHA256).
var pbkdf2Vectors = []vector{
	{Password: "password", Salt: "73616c74", Iter: 1, DKLen: 32, DK: "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"},
	{Password: "password", Salt: "73616c74", Iter: 2, DKLen: 32, DK: "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"},
	{Password: "password", Salt: "73616c74", Iter: 4096, DKLen: 32, DK: "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"},
	{Password: "passwordPASSWORDpassword", Salt: "73616c7453414c5473616c7453414c5473616c7453414c5473616c7453414c5473616c74", Iter: 4096, DKLen: 40, DK: "348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9"},
	{Password: "pass\u0000word", Salt: "7361006c74", Iter: 1, DKLen: 16, DK: "f9b77371b5a5a07700e7d9cf93dffb8f"},
	{Password: "пароль", Salt: "d181d0bed0bbd191d0bdd18bd0b92d73616c74", Iter: 1000, DKLen: 20, DK: "bcc5284801c963b4942797ec3ddcb729e390ad3b"},
}
