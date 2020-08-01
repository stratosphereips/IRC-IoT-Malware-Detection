@load base/bif/plugins/Zeek_IRC.events.bif.zeek

module Strato11;

type irc_nick_record: record {
    ts: time &log;
    orig_h: addr &log;
    orig_p: port &log;
    resp_h: addr &log;
    resp_p: port &log;
    
    who: string &log;
    newnick: string &log;
};

global irc_nick_vec: vector of irc_nick_record = vector();

export {
   redef enum Log::ID += { LOG };
}

event zeek_init() {
   Log::create_stream(Strato11::LOG, [$columns=irc_nick_record, $path="irc_nick"]);
}

event zeek_done() {
   for (i in irc_nick_vec) {
       Log::write( Strato11::LOG, irc_nick_vec[i]);
   }
}

# Generated for an IRC reply of type nick
# C:	The connection.
# Is_orig:	True if the command was sent by the originator of the TCP connection.
# Who:	The user changing its nickname.
# Newnick:	The new nickname.
event irc_nick_message(c: connection, is_orig: bool, who: string, newnick: string) {
    local rec: irc_nick_record = irc_nick_record($ts=c$irc$ts, $orig_h=c$irc$id$orig_h, $orig_p=c$irc$id$orig_p, $resp_h = c$irc$id$resp_h, $resp_p=c$irc$id$resp_p, $who=who, $newnick=newnick);
    irc_nick_vec += rec;
}
