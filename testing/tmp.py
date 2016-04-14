import soundcloud
client = soundcloud.Client(client_id='a04f0dbf1b28a8c05d920d5818371653')

urls = [
    'https://soundcloud.com/travisscott-2/wonderful-ftthe-weeknd',
    'https://soundcloud.com/davidcharlesbailey/pink-guy-ft-filthy-frank-balls-in-my-face',
    'https://soundcloud.com/yungwallstreet/tove-lo-talking-body-yung-wall-street-flip',
    'https://soundcloud.com/mako-vip/smoke-filled-room-vs-the-buzz-makohermitude',
    'https://soundcloud.com/allureproduction/allure-in-love',
    'https://soundcloud.com/maneatingoranges/i-need-to-stop',
    'https://soundcloud.com/towkio/heaven-only-knows-ft-chance-the-rapper-lido-2',
    'https://soundcloud.com/floetic-1/bryson-tiller-dont-j-louis-remix',
    'https://soundcloud.com/matoma-official/mynga-back-home-matoma-remix',
    'https://soundcloud.com/bruiseprincess/onigiri-rice-balls-filthy-frank-pink-guy'
]

for url in urls:
    track = client.get('/resolve', url=url)
    stream_url = client.get(track.stream_url, allow_redirects=False)
    print(stream_url.location)