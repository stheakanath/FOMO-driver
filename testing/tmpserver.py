from flask import Flask, Response
import json

app = Flask(__name__)

@app.route('/api/test', methods = ['GET'])
def get_songs():
    data = [
        'https://cf-media.sndcdn.com/8O8NOaEx1pAz.128.mp3?Policy=eyJTdGF0ZW1lbnQiOlt7IlJlc291cmNlIjoiKjovL2NmLW1lZGlhLnNuZGNkbi5jb20vOE84Tk9hRXgxcEF6LjEyOC5tcDMiLCJDb25kaXRpb24iOnsiRGF0ZUxlc3NUaGFuIjp7IkFXUzpFcG9jaFRpbWUiOjE0NjA1MjI1MTh9fX1dfQ__&Signature=fr23UQcghLzscqSMKhHKRPVqcuUW3F9zxqsL5oXKZZ9h6hc6ACiavdd1PN~NQzajrzu9ItJpW8fZ2K7kqR7fv1zcyeqIMP7tMph1q2bK68ttDWItxwhiywYDRJl4KvuMdMvLs5oBk94OmeB-TiLNZQqyeO3twOPpYYXWyZQZSFTUf-HebZKctnUkG4Ml3slyOWnPb5aL0Z9Tv0e4Tk8bU6AkVLfXNyaBDst9x~rJjejoaJQVV-obp0Xcdn357BGZVMhse1iUS2YxEzX5OH-ChPbDVDnNp25ERQmOAnMY~KsO3QCBglavooXIGKLD0FG5xy5wLFN1AfTEmRFQ~Efe8A__&Key-Pair-Id=APKAJAGZ7VMH2PFPW6UQ',
        'https://cf-media.sndcdn.com/7ZZ73TdnJNjb.128.mp3?Policy=eyJTdGF0ZW1lbnQiOlt7IlJlc291cmNlIjoiKjovL2NmLW1lZGlhLnNuZGNkbi5jb20vN1paNzNUZG5KTmpiLjEyOC5tcDMiLCJDb25kaXRpb24iOnsiRGF0ZUxlc3NUaGFuIjp7IkFXUzpFcG9jaFRpbWUiOjE0NjA1MjIzOTR9fX1dfQ__&Signature=lIjtjZCjiStcrwZB27lyMZojffjdAWqjdPHffpMkSBoutvm7HEnZeCR4GGy-imJP~zgctBwEl-JI~SPXWfpNRreRIYwR0OcFR0cqdfmd8SGiJcCacCuNwf60CZ2r8qWQizdRDHrt0YUfedPRx6jo87SjQ9akuEp0olchHTbC8iFUfezxzkBEPjHpO-UwDQycN4-doczHfWLIwa9PXpxZd2hyhV6HsTKCRrBSdvzVkmoJHBRZnyPUlzze9FdU5yidaSVZ~G-Quy-YMPnIsoz8h1ggRinVGfnQiVGTEUuKCKNdX9~omPFdegSPgfX93UNrEX1RVwXnOCJjpBWWHgT2Ow__&Key-Pair-Id=APKAJAGZ7VMH2PFPW6UQ',
        'https://ec-media.sndcdn.com/yur3LftU62vx.128.mp3?f10880d39085a94a0418a7ef69b03d522cd6dfee9399eeb9a522079c6afabc39fa0442c74bac23142e492938336eebdab6a809ddc58d3cecd975133855d118c4aeb91e7da7',
        'https://cf-media.sndcdn.com/0ackQqjALuxl.128.mp3?Policy=eyJTdGF0ZW1lbnQiOlt7IlJlc291cmNlIjoiKjovL2NmLW1lZGlhLnNuZGNkbi5jb20vMGFja1FxakFMdXhsLjEyOC5tcDMiLCJDb25kaXRpb24iOnsiRGF0ZUxlc3NUaGFuIjp7IkFXUzpFcG9jaFRpbWUiOjE0NjA1MjI1MDZ9fX1dfQ__&Signature=n3In78mygm0e1Tfm3GJz6quueIbTo1VGVFuYsxg0lzuMDWyw38O4dMh1cozri9NGfmKzZi2Ck-J4~Kg8ER5Ape~D25IJ0rXjRCGRLqRiSLtxs~fnGliNScvoDqE7M-v9HnBGakPonKus3YRc2J6bEEc2Q9~DcAWMBl1YGKSC5jBg--cAubN5DjhCy3wv2yr7UgIcRHXDyzL~cQ83U9a0o8NWPPPnwbD6Vy7R1NrEK3MTrjvw6UInWnBej5uS52opQ5KrZlXjC9aP8aGe5u6pmP5eURcDQRUGj97XCPq4lxv0oipwiEfWnR0Eui-IZJ0VhsEq7VukhiKdsl5G3IPs6g__&Key-Pair-Id=APKAJAGZ7VMH2PFPW6UQ',
        'https://cf-media.sndcdn.com/bhMS43GHU8Wn.128.mp3?Policy=eyJTdGF0ZW1lbnQiOlt7IlJlc291cmNlIjoiKjovL2NmLW1lZGlhLnNuZGNkbi5jb20vYmhNUzQzR0hVOFduLjEyOC5tcDMiLCJDb25kaXRpb24iOnsiRGF0ZUxlc3NUaGFuIjp7IkFXUzpFcG9jaFRpbWUiOjE0NjA1MjI1NTN9fX1dfQ__&Signature=Z2VouhisOWboFPrvg0EeQFIGA2EoJdVYH8W6gFE-RwwR-ltJLvngOL7PXw13SeUldlfEF8jvA~3nO5X0Gf2rbfhyE3m1yL2Im8a3rN5ZR0pKeA1Oxv3U8W4gsIXcC2z9p1bti~8RnP~XJnAeCnBwphxnZh4le~NMTq9vBgZaehpXG9kZNyeNIxJ4PazIIuZKYSBHi0NoVcC3AWjQ0MMWOj-M0UJp3kf4HpeVNRrqRSFAKMjVwFO7dWbs05yOdHhbPyRroe~cDL3P5qB4WzxalrxU1PAg1wtY5emmiJHJ2Fxklo8geUU8kPWJfGvYsmUD6G3CspMcQIQmtdjXqI7z8Q__&Key-Pair-Id=APKAJAGZ7VMH2PFPW6UQ',
        'https://cf-media.sndcdn.com/VrudeoMh4oRf.128.mp3?Policy=eyJTdGF0ZW1lbnQiOlt7IlJlc291cmNlIjoiKjovL2NmLW1lZGlhLnNuZGNkbi5jb20vVnJ1ZGVvTWg0b1JmLjEyOC5tcDMiLCJDb25kaXRpb24iOnsiRGF0ZUxlc3NUaGFuIjp7IkFXUzpFcG9jaFRpbWUiOjE0NjA1MjI0MDl9fX1dfQ__&Signature=x1zor9-ttQBi8l0vndxMKctsFnRFCcvshIazH4NLAqVsneX6LTpCqZmTLF1F3V~SkUYn2lBwLQNrDC6iLoyKXpivIe8PalpCoOtAQdORB9EsAT7GOEHqbNOifylo3-9QYCEfqQASQG~rXE2xNiiQX-4irfpUMUW5kN9TTw3zZ8yzE3FyVOzsG2kKu1OvJSvAL86PVEnX~BSMqWajaJF73r8irrAdJ0yAIo1XxEJiV2c7OPowhVxfmlwjlxrYCoxVUGdH1eLOoHPyRau1R6RhVkiWyugOaX876Z5k8bOWL2fNklGx8VZpT5hMAHgcYL42GiQM4sZ7sXfMwTgo5x82gQ__&Key-Pair-Id=APKAJAGZ7VMH2PFPW6UQ',
        'https://cf-media.sndcdn.com/4pMplGGUlRPP.128.mp3?Policy=eyJTdGF0ZW1lbnQiOlt7IlJlc291cmNlIjoiKjovL2NmLW1lZGlhLnNuZGNkbi5jb20vNHBNcGxHR1VsUlBQLjEyOC5tcDMiLCJDb25kaXRpb24iOnsiRGF0ZUxlc3NUaGFuIjp7IkFXUzpFcG9jaFRpbWUiOjE0NjA1MjI1Mjh9fX1dfQ__&Signature=uc4Yj-~j6p2xGryIxQfcdO~9e8l0DbVT3NrQJTBQGQExa5d5vgpA2N284GLlR-4yrNatSSYddVlj0z9Wbu8TyUC0Hd00MNWiYZLpa1ehkc~75TYXTCqcpk9wBekKjX62fqQ83EtWrwqoLXxobSl5d5YwFReYkmDeekuM5fe4sBXiU~PVHcEUJK9T9qyviHLu63dqO0wlOoUdILskG-MSRuCy9AMF8eq7UrhaYlZvHkueJp03jGQxjsJG4LD5kabl8Gq6wZ3AHUqRGWupnkMNTbT7AzEE4oLZXq-zN-1I5lDK9S8BVhK4viUvdaDFuQ-99KuQXsiDsfDw-YqaVN8cQg__&Key-Pair-Id=APKAJAGZ7VMH2PFPW6UQ',
        'https://ec-media.sndcdn.com/o8u6rlybM4mI.128.mp3?f10880d39085a94a0418a7ef69b03d522cd6dfee9399eeb9a522079c6afabc3849cef2c2c86015c2dc5b0152e3b8e90ead34c4b86aea2d46ffc307f54518fd93824b0b42f1',
        'https://ec-media.sndcdn.com/hqEWEhVkYZQV.128.mp3?f10880d39085a94a0418a7ef69b03d522cd6dfee9399eeb9a522079c6afabc39ff0742c74bac231460077b95ba64cd1e2141602a6bfa451404e435dc4921383409f88594b6',
        'https://cf-media.sndcdn.com/nuBl94hb1Iyk.128.mp3?Policy=eyJTdGF0ZW1lbnQiOlt7IlJlc291cmNlIjoiKjovL2NmLW1lZGlhLnNuZGNkbi5jb20vbnVCbDk0aGIxSXlrLjEyOC5tcDMiLCJDb25kaXRpb24iOnsiRGF0ZUxlc3NUaGFuIjp7IkFXUzpFcG9jaFRpbWUiOjE0NjA1MjI1MDl9fX1dfQ__&Signature=kdhWSDdO-RCLwCtq3RL5dZShSwZqc1PsLjZIcJqiKHhkxTW5cC7uayf59xLzQF1UmGVp6sAgnz5roAn48mbFH5GpZYvG~MWc2h1XMNfCqzF0xlesgcDP5dX7tzjNCD-cnqPNYcX23dPHLGs5yL0g5wv920sYgG6SYcRvd4F5VTfu1bwYlIvI6Nt3NwJZLJuc2ND5mTBFG6zuDn5iDtCyRZQwHx4p8j-mB1q3AstgeXkOhZKTmb4J3vY75I2kHz~1QerXwuZcuUq3T5fhMOcnyFndNmMBWIbS31g-7N2RCIniU48m9fS8EwHDjjO2jpeI47K1qAd3gTrwREk2TxpG~Q__&Key-Pair-Id=APKAJAGZ7VMH2PFPW6UQ'
    ]
    js = json.dumps(data)
    resp = Response(js, status=200, mimetype='application/json')
    return resp

if __name__ ==  '__main__' :
    app.run(debug=True)
