import soundcloud
import config

hip_hop_genres = ['hiphop', 'hip hop', 'Hip-hop & Rap', 'hip-hop']
edm_genres = [] # TODO
# TODO: Add more genres here

# Returns a list of comments
def get_all_comments(client, song):
    """
    Returns all comments for a song

    Args:
      client: soundcloud.Client object
      song: soundcloud.resource.Resource object

    Returns:
      see description
    """
    comment_list = []
    link = '/tracks/%d/comments' % song.id
    comments = client.get(link, linked_partitioning=1)
    while True:
        for comment in comments.collection:
            comment_list.append(comment)
        if not hasattr(comments, 'next_href'):
            break
        comments = client.get(comments.next_href, linked_partitioning=1)

    return comment_list


def get_comment_samples(client, song):
    """
    Returns a hopefully-representative sample of comments for a song

    Args:
      client: soundcloud.Client object
      song: soundcloud.resource.Resource object

    Returns:
      see description
    """
    link = '/tracks/%d/comments' % song.id
    return client.get(link).collection


def get_start_time(client, song, duration=30):
    """
    Finds the best start time for a song

    Args:
      client: soundcloud.Client object
      song: soundcloud.resource.Resource object
      duration: interval

    Returns:
      see description
    """
    comments = get_comment_samples(client, song)


