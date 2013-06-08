#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import hashlib
import time
import re

import listparser
import feedparser
import urlnorm

from pylyskom import komauxitems
from pylyskom import kom
from httpkom import komsession


# TODO:
#
# - presentation för skapade möten
# - länk till bloggen från presentationen
# - länk till blogginlägget från text
# - hitta feeds i en webbsida (så man kan ange en blogg-url och inte behöver leta upp feed-urlen)
# - kunna visa bloggnamnet istället för "Feed (-) <url>" (dvs något i stil med alternate-name)
# - spara e-tag, last updated eller liknande som metadata på conf för blogg
# - hantera maxlängd på mötesnamn (hur ska vi matcha url om inte hela får plats?) Kan vi öka max?
# - hantera att feeds inte finns (404 kan vara temporärt)

# - flytta komsession till pylyskom


#lyskom_host = 'localhost'
lyskom_host = 'strela.intresseklubben.org'
lyskom_port = 4894

komfeeder_name = 'komfeeder'
#komfeeder_password = 'test123'
komfeeder_password = 'facit24facit24'


# Max conference name length
LYSKOM_MAX_CONFERENCE_NAME_LENGTH = 60



def find_feed_urls(data):
    if 'links' not in data.feed:
        return []
    
    feed_urls = []
    for l in data.feed['links']:
        if 'rel' in l and l['rel'] == 'alternate' and 'url' in l:
            feed_urls.append(l['url'])

    return feed_urls


def parse_feed(url):
    print "Feedparser: Fetching '%s'." % (url,)
    d = feedparser.parse(url)
    print "Feedparser: Parsed '%s'." % (url,)

    # Detect feed urls from html page
    #print find_feed_urls(d)
    
    #print d
    #print d.feed
    #print d.status
    #print d.headers
    #print d.version
    #print d.feed.title
    #print d.feed.link
    #print d.entries

    # It seems we can handle bozo feeds, so don't check for that.
    #if d.bozo:
    #    raise Exception("Bozo flag was set for url: '%s'" % (url,))
    
    if not d.feed:
        if 'bozo_exception' in d:
            raise d.bozo_exception
    if 'status' in d and d.status == 404:
        raise Exception("Feed does not exist. Got 404 for url: '%s'." % (url,))
    if not d.version:
        if 'content-type' in d.headers:
            raise Exception("Got unexpected content type '%s' for url: '%s'" % (
                    d.headers['content-type'], url))
        else:
            raise Exception("Unknown feed type '%s' for url: '%s'" % (d.version, url))
    if 'link' not in d.feed:
        raise Exception("Could not find feed link for url: '%s'" % (url,))
    if 'title' not in d.feed:
        raise Exception("Could not find feed title for url: '%s'" % (url,))
    print "Feedparser: Found feed named: '%s'." % d.feed.title
    return d


def create_lyskom_session():
    ksession = komsession.KomSession(lyskom_host, lyskom_port)
    ksession.connect('komfeeder', '0.1')
    print "LysKOM: Connected."
    pers_no = ksession.lookup_name_exact(komfeeder_name, want_pers=True, want_confs=False)
    ksession.login(pers_no, komfeeder_password)
    print "LysKOM: Logged in."
    return ksession


def normalize_url(url):
    norm_url = urlnorm.norm(url)
    if norm_url.startswith("https://"):
        return norm_url[8:]
    elif norm_url.startswith("http://"):
        return norm_url[7:]
    else:
        return norm_url


def get_conf_name_for_feed(feed):
    feed_url = normalize_url(feed.link)
    name = "Feed (-) {url}".format(url=feed_url)
    return name[:LYSKOM_MAX_CONFERENCE_NAME_LENGTH]


def find_conf_for_feed(ksession, feed):
    conf_name = get_conf_name_for_feed(feed)
    
    try:
        conf_no = ksession.lookup_name_exact(conf_name, want_pers=False, want_confs=True)
    except komsession.NameNotFound:
        print "LysKOM: Did not find conference '%s'." % (conf_name,)
        conf_no = create_conf(ksession, conf_name)

    conf = ksession.get_conference(conf_no, micro=False)
    print "LysKOM: Found conference: '%s'." % conf.name
    if conf.creator != ksession.get_person_no():
        raise Exception("I am not the creator of this conference. Aborting!")
    return conf


def create_conf(ksession, conf_name):
    try:
        conf_no = ksession.create_conf(conf_name)
        print "LysKOM: Created conference : (%d) '%s'." % (conf_no, conf_name)
        return conf_no
    except kom.ConferenceExists:
        raise Exception("Failed to create conference: '%s'." % conf_name)


def get_message_id_from_text(text):
    if text.aux_items is None:
        return None
    
    for ai in text.aux_items:
        if ai.tag == komauxitems.AI_MX_MESSAGE_ID:
            return ai.data

    return None


def get_content_for_entry(entry):
    if 'content' in entry:
        #if len(entry.content) != 1:
        #    print entry.content
        #    raise Exception("Feed entry has unhandled number of contents: %d" % len(entry.content))
        return entry.content[0]
    elif 'summary_detail' in entry:
        return entry.summary_detail
    else:
        return { 'value': "", 'type': 'text/plain' }


def get_id_for_entry(entry):
    if 'id' in entry:
        return entry.id
    else:
        return entry.link


def get_published_for_entry(entry):
    if 'published_parsed' in entry and entry.published_parsed:
        return entry.published_parsed
    elif 'updated_parsed' in entry and entry.updated_parsed:
        return entry.updated_parsed
    else:
        return None


def create_message_id(entry):
    m = hashlib.sha256()
    # Stuff that all should be the same for one entry to be consider
    # identical to another.
    #print entry
    m.update(get_id_for_entry(entry).encode('utf-8'))
    m.update(entry.title.encode('utf-8'))
    m.update(get_content_for_entry(entry)['value'].encode('utf-8'))
    digest = m.hexdigest()
    message_id = "<" + digest + "@komfeeder>"
    return message_id


def import_feed_to_conf(ksession, data, conf):
    entries = sorted(data.entries, key=lambda e: get_published_for_entry(e))
    last_texts = get_last_texts(ksession, conf, max(100, len(entries)))
    last_text_message_ids = [ get_message_id_from_text(t) for t in last_texts ]
    existing_message_ids = set([ m_id for m_id in last_text_message_ids if m_id is not None ])
    
    # Create texts, starting with the oldest.
    num_skipped = 0
    for e in entries:
        message_id = create_message_id(e)
        if message_id not in existing_message_ids:
            create_text_for_entry(ksession, conf, data.feed, e, message_id)
        else:
            num_skipped += 1
            #print "Message ID for '%s' already exists. Skipping." % (e.link,)
    if num_skipped > 0:
        print "Skipped %d entries that already existed." % (num_skipped,)


def get_last_texts(ksession, conf, num_last_texts):
    last_texts = ksession.get_last_texts(conf.conf_no, num_last_texts)
    return last_texts    


_content_type_map = {
    'text/html': 'text/html',
    'application/xhtml+xml': 'text/html',
    'text/plain': 'text/plain' }

def create_text_for_entry(ksession, conf, feed, entry, message_id):
    komtext = komsession.KomText()
    komtext.recipient_list = [ kom.MIRecipient(type=kom.MIR_TO, recpt=conf.conf_no) ]
    komtext.subject = entry.title

    content = get_content_for_entry(entry)
    if content['type'] not in _content_type_map:
        raise Exception("Feed entry has unhandled content type: %s" % content['type'])
    
    mime_type, encoding = komsession.parse_content_type(_content_type_map[content['type']])
    komtext.content_type = komsession.mime_type_tuple_to_str(mime_type)
    komtext.body = content['value']
    
    #print content
    #raise Exception()
    #print komsession.to_dict(komtext, lookups=True, session=ksession)
    #print komtext.subject, entry.published
    
    komtext.aux_items = []
    komtext.aux_items.append(kom.AuxItem(komauxitems.AI_MX_MESSAGE_ID, data=message_id))
    
    published_date = get_published_for_entry(entry)
    if published_date is not None:
        komtext.aux_items.append(kom.AuxItem(
                komauxitems.AI_MX_DATE,
                data=time.strftime("%Y-%m-%d %H:%M:%S +0000", published_date)))
    
    if 'author_detail' in entry:
        if 'name' in entry.author_detail and len(entry.author_detail.name) > 0:
            author = entry.author_detail.name
        elif 'email' in entry.author_detail and len(entry.author_detail.email) > 0:
            author = entry.author_detail.email
        else:
            author = feed.title
    else:
        author = feed.title
    komtext.aux_items.append(kom.AuxItem(komauxitems.AI_MX_AUTHOR, data=author))
    
    try:
        text_no = ksession.create_text(komtext)
        print "LysKOM: Created text no: %d" % text_no
    except:
        raise


def import_feed(ksession, url):
    data = parse_feed(url)
    conf = find_conf_for_feed(ksession, data.feed)
    if conf is None:
        raise Exception("Failed to find conference for url: '%s'." % (url,))
    import_feed_to_conf(ksession, data, conf)


def import_feeds(urls):
    ksession = create_lyskom_session()

    print "Importing %d feeds." % (len(urls),)
    for url in urls:
        import_feed(ksession, url)

    ksession.disconnect()
    print "LysKOM: Disconnected."
    

def read_opml(filename):
    print "OPML: Reading OPML file: '%s'." % (filename,)
    result = listparser.parse(filename)
    urls = [ f.url for f in result.feeds ]
    #print urls
    return urls


def main(argv):
    urls = [
        #"http://www.ofiltrerat.se/feeds/posts/default",
        #"http://blog.osd.se/feed/",
        #"http://bacon.hornfeldt.se/feed/atom/",
        #"http://blog.svd.se/maratonbloggen/feed/",
        #"http://annhelenarudberg1.blogspot.com/feeds/posts/default",
        #"http://www.swedroid.se/feed/",
        #"http://feeds.feedburner.com/weightwatcherspointsrecipes",
        #"http://10000shots.com/rss",
        #"http://briantford.com/blog.rss",
        #"http://www.allthingsdistributed.com/atom.xml",
        #"http://dustin.github.com/atom.xml",
        #"http://jzawodn.com/rss.xml",
        #"http://www.kickstarter.com/projects/zpmespresso/pid-controlled-espresso-machine/posts.atom",
        #"http://feeds.feedburner.com/OdeToCode",
        #"http://what-if.xkcd.com/feed.atom",
        #"http://feeds2.feedburner.com/hunch",
        #"http://intertwingly.net/blog/index.atom",
        #"http://feeds.feedburner.com/herdingcode",


        # TODO: De här finns inte, men d.status = 301 istället för 404.
        #"http://jagregory.com/feed/",
        #"http://www.johanochnystrom.se/rss/rss.xml",
        #"http://feedproxy.google.com/londinium-espresso-blog",

        # TODO: Har något som inte kan kodas till latin1.
        #"http://feeds.pagetracer.com/pagetracer'"

        # TODO: Tecken som inte kan kodas till latin1 (dvs något som används i aux-items)
        #"http://feeds.feedburner.com/bin/recykl",

        ]
    
    if len(argv) > 1:
        urls = read_opml(argv[1])
    
    import_feeds(urls)


if __name__ == "__main__":
    main(sys.argv)
