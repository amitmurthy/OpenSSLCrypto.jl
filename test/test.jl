using OpenSSL.Crypto
using Base.Test
using Codecs

s = Crypto.hmacsha256_digest(
    "GET\nelasticmapreduce.amazonaws.com\n/\nAWSAccessKeyId=AKIAIOSFODNN7EXAMPLE&Action=DescribeJobFlows&SignatureMethod=HmacSHA256&SignatureVersion=2&Timestamp=2011-10-03T15%3A19%3A30&Version=2009-03-31",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
                    
sb64 = bytestring(Codecs.encode(Base64, s))

#println("Output bytes : $sl, b64 : $sb64")

@test "i91nKc4PWAt0JJIdXwz9HxZCJDdiy6cf/Mj6vPxyYIs=" == sb64
println("PASSED : HMAC-SHA256")


s = Crypto.hmacsha1_digest(
    "GET\n\n\nTue, 27 Mar 2007 19:36:42 +0000\n/johnsmith/photos/puppy.jpg",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
                    
sb64 = bytestring(Codecs.encode(Base64, s))


#println("Output bytes : $sl, b64 : $sb64")

@test "bWq2s1WEIj+Ydj0vQ697zp+IXMU=" == sb64
println("PASSED : HMAC-SHA1")


d="Just a really long string......Just a really long string......Just a really long string......Just a really long string......Just a really long string......Just a really long string......"
sb = bytes2hex(Crypto.md5(d))

@test "5c0614d60fb48f8f318c3578ca959120" == sb
println("PASSED : MD5")


repeat="hello"
xtimes=100000
real_long_string = ^(repeat, xtimes)

iob = IOBuffer(length(repeat) * xtimes) 
write(iob, real_long_string)

seekstart(iob)

iomd5 = bytes2hex(Crypto.md5(iob))

smd5 = bytes2hex(Crypto.md5(real_long_string))

@test iomd5 == smd5
println("PASSED : IO MD5")

