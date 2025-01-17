package test

// TLSCertPub is the public key of a dummy certificate.
var TLSCertPub = []byte(`-----BEGIN CERTIFICATE-----
MIIDazCCAlOgAwIBAgIUXw1hEC3LFpTsllv7D3ARJyEq7sIwDQYJKoZIhvcNAQEL
BQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDAeFw0yMDEyMTMxNzQ0NThaFw0zMDEy
MTExNzQ0NThaMEUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw
HwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQDG8DyyS51810GsGwgWr5rjJK7OE1kTTLSNEEKax8Bj
zOyiaz8rA2JGl2VUEpi2UjDr9Cm7nd+YIEVs91IIBOb7LGqObBh1kGF3u5aZxLkv
NJE+HrLVvUhaDobK2NU+Wibqc/EI3DfUkt1rSINvv9flwTFu1qHeuLWhoySzDKEp
OzYxpFhwjVSokZIjT4Red3OtFz7gl2E6OAWe2qoh5CwLYVdMWtKR0Xuw3BkDPk9I
qkQKx3fqv97LPEzhyZYjDT5WvGrgZ1WDAN3booxXF3oA1H3GHQc4m/vcLatOtb8e
nI59gMQLEbnp08cl873bAuNuM95EZieXTHNbwUnq5iybAgMBAAGjUzBRMB0GA1Ud
DgQWBBQBKhJh8eWu0a4au9X/2fKhkFX2vjAfBgNVHSMEGDAWgBQBKhJh8eWu0a4a
u9X/2fKhkFX2vjAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQBj
3aCW0YPKukYgVK9cwN0IbVy/D0C1UPT4nupJcy/E0iC7MXPZ9D/SZxYQoAkdptdO
xfI+RXkpQZLdODNx9uvV+cHyZHZyjtE5ENu/i5Rer2cWI/mSLZm5lUQyx+0KZ2Yu
tEI1bsebDK30msa8QSTn0WidW9XhFnl3gRi4wRdimcQapOWYVs7ih+nAlSvng7NI
XpAyRs8PIEbpDDBMWnldrX4TP6EWYUi49gCp8OUDRREKX3l6Ls1vZ02F34yHIt/7
7IV/XSKG096bhW+icKBWV0IpcEsgTzPK1J1hMxgjhzIMxGboAeUU+kidthOob6Sd
XQxaORfgM//NzX9LhUPk
-----END CERTIFICATE-----
`)

// TLSCertKey is the private key of a dummy certificate.
var TLSCertKey = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAxvA8skudfNdBrBsIFq+a4ySuzhNZE0y0jRBCmsfAY8zsoms/
KwNiRpdlVBKYtlIw6/Qpu53fmCBFbPdSCATm+yxqjmwYdZBhd7uWmcS5LzSRPh6y
1b1IWg6GytjVPlom6nPxCNw31JLda0iDb7/X5cExbtah3ri1oaMkswyhKTs2MaRY
cI1UqJGSI0+EXndzrRc+4JdhOjgFntqqIeQsC2FXTFrSkdF7sNwZAz5PSKpECsd3
6r/eyzxM4cmWIw0+Vrxq4GdVgwDd26KMVxd6ANR9xh0HOJv73C2rTrW/HpyOfYDE
CxG56dPHJfO92wLjbjPeRGYnl0xzW8FJ6uYsmwIDAQABAoIBACi0BKcyQ3HElSJC
kaAao+Uvnzh4yvPg8Nwf5JDIp/uDdTMyIEWLtrLczRWrjGVZYbsVROinP5VfnPTT
kYwkfKINj2u+gC6lsNuPnRuvHXikF8eO/mYvCTur1zZvsQnF5kp4GGwIqr+qoPUP
bB0UMndG1PdpoMryHe+JcrvTrLHDmCeH10TqOwMsQMLHYLkowvxwJWsmTY7/Qr5S
Wm3PPpOcW2i0uyPVuyuv4yD1368fqnqJ8QFsQp1K6QtYsNnJ71Hut1/IoxK/e6hj
5Z+byKtHVtmcLnABuoOT7BhleJNFBksX9sh83jid4tMBgci+zXNeGmgqo2EmaWAb
agQslkECgYEA8B1rzjOHVQx/vwSzDa4XOrpoHQRfyElrGNz9JVBvnoC7AorezBXQ
M9WTHQIFTGMjzD8pb+YJGi3gj93VN51r0SmJRxBaBRh1ZZI9kFiFzngYev8POgD3
ygmlS3kTHCNxCK/CJkB+/jMBgtPj5ygDpCWVcTSuWlQFphePkW7jaaECgYEA1Blz
ulqgAyJHZaqgcbcCsI2q6m527hVr9pjzNjIVmkwu38yS9RTCgdlbEVVDnS0hoifl
+jVMEGXjF3xjyMvL50BKbQUH+KAa+V4n1WGlnZOxX9TMny8MBjEuSX2+362vQ3BX
4vOlX00gvoc+sY+lrzvfx/OdPCHQGVYzoKCxhLsCgYA07HcviuIAV/HsO2/vyvhp
xF5gTu+BqNUHNOZDDDid+ge+Jre2yfQLCL8VPLXIQW3Jff53IH/PGl+NtjphuLvj
7UDJvgvpZZuymIojP6+2c3gJ3CASC9aR3JBnUzdoE1O9s2eaoMqc4scpe+SWtZYf
3vzSZ+cqF6zrD/Rf/M35IQKBgHTU4E6ShPm09CcoaeC5sp2WK8OevZw/6IyZi78a
r5Oiy18zzO97U/k6xVMy6F+38ILl/2Rn31JZDVJujniY6eSkIVsUHmPxrWoXV1HO
y++U32uuSFiXDcSLarfIsE992MEJLSAynbF1Rsgsr3gXbGiuToJRyxbIeVy7gwzD
94TpAoGAY4/PejWQj9psZfAhyk5dRGra++gYRQ/gK1IIc1g+Dd2/BxbT/RHr05GK
6vwrfjsoRyMWteC1SsNs/CurjfQ/jqCfHNP5XPvxgd5Ec8sRJIiV7V5RTuWJsPu1
+3K6cnKEyg+0ekYmLertRFIY6SwWmY1fyKgTvxudMcsBY7dC4xs=
-----END RSA PRIVATE KEY-----
`)

// TLSCertPubAlt is the public key of an alternative dummy certificate.
var TLSCertPubAlt = []byte(`-----BEGIN CERTIFICATE-----
MIIDSTCCAjECFEut6ZxIOnbxi3bhrPLfPQZCLReNMA0GCSqGSIb3DQEBCwUAMGEx
CzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRl
cm5ldCBXaWRnaXRzIFB0eSBMdGQxGjAYBgNVBAMMEW1lZGlhbXR4LnRlc3QuY29t
MB4XDTI0MDgwMTIzNDY0MloXDTM0MDczMDIzNDY0MlowYTELMAkGA1UEBhMCQVUx
EzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMg
UHR5IEx0ZDEaMBgGA1UEAwwRbWVkaWFtdHgudGVzdC5jb20wggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQCzfvG9eLXKSTDBoM+cgV/ThiNRI2JY6dpQV8rK
QFQ5bkkDUDP+2Ae/IWylgLLXmozsMwjz1Pu42awmGymBuo5HDbI4bxPJNQR9qRrR
2+MvfDgmZxyhw5NfZDlVl+enxhb3FRgbHsLBy4oSoHbRUdLApVdM0Kg6r3bXzkih
EEs63boFJOkPhs5H0NX7AzXyBp2WnvB71j+7avnMwAsjJHOiTs8wkp5wvRcIZpJl
MCandUkcZShMirug7QOcR9fAr5CVKxsO/DjqEjwkslJHFfizOl3yRx6nsxvW8JUd
dforpSRj84dkHTi7k37YTiji90GsOvh0qc0MfAmeE181HIb/AgMBAAEwDQYJKoZI
hvcNAQELBQADggEBAEWkLL/7nvt3iD7BVJNHLvAS6GwuTH99vCil6TFYwVl4goht
Dur7YfzN43vUq+lAwS3Ry4ka7tH72pAMkpNFRvHOikWGmWUSDo2DcLd8iu3ruLF7
yUg2ASQuekK0sUv4YKpAqV8gS2R4Jh4vLU+8L5iJ1XWGELbQ+H5wm4l7l+r2X6cD
/opmdV8Slfi0FlNQtflLsGoSlfZF5jHxqi3zyt8QdEf9WZt8e6JPxcx2Fq7Op51u
Qx9nosr5fLwhkx46+B/cotsbI/xPDjLF6RQ1OUpcHwg1HI6czoW4hHn33S0zstCf
BWt5Q1Mb2tGInbmbUgw3wUu/4nWoY+Mq4DKPlKs=
-----END CERTIFICATE-----`)

// TLSCertKeyAlt is the private key of an alternative dummy certificate.
var TLSCertKeyAlt = []byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEoQIBAAKCAQEAs37xvXi1ykkwwaDPnIFf04YjUSNiWOnaUFfKykBUOW5JA1Az
/tgHvyFspYCy15qM7DMI89T7uNmsJhspgbqORw2yOG8TyTUEfaka0dvjL3w4Jmcc
ocOTX2Q5VZfnp8YW9xUYGx7CwcuKEqB20VHSwKVXTNCoOq92185IoRBLOt26BSTp
D4bOR9DV+wM18gadlp7we9Y/u2r5zMALIyRzok7PMJKecL0XCGaSZTAmp3VJHGUo
TIq7oO0DnEfXwK+QlSsbDvw46hI8JLJSRxX4szpd8kcep7Mb1vCVHXX6K6UkY/OH
ZB04u5N+2E4o4vdBrDr4dKnNDHwJnhNfNRyG/wIDAQABAoH/WmCqV6Lv5dEnofCj
ZUO/Fdv0hf/LBS0g2SAoFRSCIM8aJ3dUUH0PaXoeINDGCMlIxT7tKXJg5jJNYhWx
g7oegw6vLe5ZiA+p5miL/uue+Jas4kLVp9DrfQLgQevt0gw4g/00pgy9adbFlTUD
a2HhPB7RIvXs8gYA6nVAT9jK1ST2pbeUgQNO4Ji4EjpPUkR2O7ISOlu5EV8Cj0eV
1Vs5B92Z7ORh7P2fFV2YBu+igd04+uYvei6slQl+F9cETvJv2Z9r37Yashvnn1in
uy/u1U4B1t4oOz81nHz6kxTixPpBOdJ6x8jLDgNGSsauJQfXT9xmB/rAr/NFq+7I
tbTNAoGBAMOgm3XXHWokmJnX9pfNj6ixNlrMuuez/yXMVwuxa2WFwAFN16tjJhBi
XOjestcvu/SRhOAMmYac5QdopJpLjO/FxO165r73eZhW/SJefyOHtfD29kHagA1u
JjcznU6tiA0O1owy6nuuaTfyVbDQj32PhVBx9ZwSI4778GFbjWl7AoGBAOrj4WCC
gTMaExpwNo+L+3VkM79YD1Obl13FcgtVoxjcoWjQeMx9D0k7adTV3xlchHFAjiD5
Gs/MZl8+seq+GDX3mODsmJkdRQbYId4g6IesiOnQ3Ug/Y282WZRnpB5h/BMnrcCZ
VoohnATA7f96c7XtPUgZyROmh24T7UIVwVdNAoGAbeeGT276TI6g2RWWqXRIOFrP
EbYhb1kViFPDt4MGtjOtSk5EUzpRwTSxw/aRfQmJS/6RKxqJCjKNDVuB1lmJpY9z
coPwrOr1+lssvalfPkPZOLZWZWrvNBxlBfBOeUxOuh9S89MLH08+N7tC3yJc6wq9
uBM+DF+4cHUkeF3qFY8CgYBzS+IwBj82/0CLRLNzaKnIqKPB846qYoA9NhLRv3ps
VLgiA9qXvXdIYhKDt2toPoKAOMjLJJtljpZdgB/C8wZdTyjKlzgcSEK+pk6RgyPA
nQ8jfjNwKDU9vLbh4rGrfDtIh7yBAoN5ECBOMQlh0xCDJ21iO834iFCH1t4qBxW9
LQKBgQC36adC2Gu+FJRvx4Mkm73fLmVdFbP6Do7qNwyVVyaG80PDVrFQrlWm4Dt7
AO9IwzaS1Lx+qmU1Fj1WfCtXuQa5nc9AzZ36TmM6+pAn8AC7PdNqc0qSdefVrIjj
zRGhUPaJV3A+sfO+xedBsAFnqNuX9oODYVGbTjuc2OWC30MGaw==
-----END RSA PRIVATE KEY-----
`)
