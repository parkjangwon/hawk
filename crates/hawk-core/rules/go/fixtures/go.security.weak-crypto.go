// ruleid: go.security.weak-crypto
h := md5.New()
// ruleid: go.security.weak-crypto
s := sha1.Sum(data)
// ok: go.security.weak-crypto
h256 := sha256.New()
