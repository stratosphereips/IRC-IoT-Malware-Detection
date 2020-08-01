@load base/bif/plugins/Zeek_IRC.events.bif.zeek

module Strato5;

type irc_invalid_nick_record: record {
    ts: time &log;
    orig_h: addr &log;
    orig_p: port &log;
    resp_h: addr &log;
    resp_p: port &log;
    
    prefix: string &log &optional;
    message: string &log &optional;
};

global irc_invalid_nick_vec: vector of irc_invalid_nick_record = vector();

export {
   redef enum Log::ID += { LOG };
}

event zeek_init() {
   Log::create_stream(Strato5::LOG, [$columns=irc_invalid_nick_record, $path="irc_invalidnick"]);
}

event zeek_done() {
   for (i in irc_invalid_nick_vec) {
       Log::write( Strato5::LOG, irc_invalid_nick_vec[i]);
   }
}

# Generated when a server rejects an IRC nickname.
# C:	The connection.
# Is_orig:	True if the command was sent by the originator of the TCP connection.
event irc_invalid_nick(c: connection, is_orig: bool) {
    if (c?$irc) {
        local rec: irc_invalid_nick_record = irc_invalid_nick_record($ts=c$irc$ts, $orig_h=c$irc$id$orig_h, $orig_p=c$irc$id$orig_p, $resp_h = c$irc$id$resp_h, $resp_p=c$irc$id$resp_p);
        irc_invalid_nick_vec += rec;        
    }
}