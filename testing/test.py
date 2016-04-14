import soundcloud
import piq_utils
import config

client = soundcloud.Client(client_id=config.client_id)

tracks = client.get('/tracks', q='Darren Styles & Re-Con Feat Matthew Steeper - Rest Of Your Life (Robokid Hypermix)', limit=10)

test = piq_utils.get_all_comments(client, tracks[0])
