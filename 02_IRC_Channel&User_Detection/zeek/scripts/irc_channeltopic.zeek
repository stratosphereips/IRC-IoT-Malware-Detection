@load base/bif/plugins/Zeek_IRC.events.bif.zeek

module Strato2;

type irc_channeltopic_record: record {
    ts: time &log;
    orig_h: addr &log;
    orig_p: port &log;
    resp_h: addr &log;
    resp_p: port &log;
    
    channel: string &log;
    topic: string &log;
};

global irc_channeltopic_vec: vector of irc_channeltopic_record = vector();

export {
   redef enum Log::ID += { LOG };
}

event zeek_init() {
   Log::create_stream(Strato2::LOG, [$columns=irc_channeltopic_record, $path="irc_channeltopic"]);
}

event zeek_done() {
   for (i in irc_channeltopic_vec) {
       Log::write( Strato2::LOG, irc_channeltopic_vec[i]);
   }
}

# Generated for an IRC reply of type topic.
# C:	The connection.
# Is_orig:	True if the command was sent by the originator of the TCP connection.
# Channel:	The channel name specified in the reply.
event irc_channel_topic(c: connection, is_orig: bool, channel: string, topic: string) {
    if (c?$irc) {
        local rec: irc_channeltopic_record = irc_channeltopic_record($ts=c$irc$ts, $orig_h=c$irc$id$orig_h, $orig_p=c$irc$id$orig_p, $resp_h = c$irc$id$resp_h, $resp_p=c$irc$id$resp_p, $channel=channel, $topic=topic);
        irc_channeltopic_vec += rec;        
    }
}
