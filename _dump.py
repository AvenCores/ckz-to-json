import json

vs = json.load(open("internal/ccm/testdata/vectors.json"))
sel = [v for v in vs if len(v["pt"]) <= 64 and len(v["aad"]) <= 600]
print("# ccm vectors: %d of %d" % (len(sel), len(vs)))
for v in sel:
    print('{"%s", "%s", "%s", "%s", "%s", %d},' %
          (v["key"], v["nonce"], v["pt"], v["aad"], v["ct"], v["tagLen"]))

print("# kdf vectors")
for v in json.load(open("internal/kdf/testdata/vectors.json")):
    print('{"%s", "%s", "%s", %d, %d},' %
          (v["password"].encode("unicode_escape").decode(), v["salt"],
           v["dk"], v["iter"], v["dkLen"]))

print("# sample records (repr in python => go backtick check)")
for fn in ("testdata/rec1.ckz",):
    print(fn)
    print(repr(open(fn).read()))
print("# expected plaintexts")
print(repr(open("testdata/expected.json", encoding="utf-8").read()))
print("# sample line2")
print(repr(open("testdata/sample.ckz").read().splitlines()[1]))
