@load base/bif/plugins/Zeek_IRC.events.bif.zeek

module Strato16;

type irc_whois_record: record {
    ts: time &log;
    orig_h: addr &log;
    orig_p: port &log;
    resp_h: addr &log;
    resp_p: port &log;
    
    nick: string &log;
    user: string &log;
    host: string &log;
    real_name: string &log;
};

global irc_whois_vec: vector of irc_whois_record = vector();

export {
   redef enum Log::ID += { LOG };
}

event zeek_init() {
   Log::create_stream(Strato16::LOG, [$columns=irc_whois_record, $path="irc_whois"]);
}

event zeek_done() {
   for (i in irc_whois_vec) {
       Log::write( Strato16::LOG, irc_whois_vec[i]);
   }
}

event irc_whois_user_line (c: connection, is_orig: bool, nick: string, user: string, host: string, real_name: string) {
    local rec: irc_whois_record = irc_whois_record($ts=c$irc$ts, $orig_h=c$irc$id$orig_h, $orig_p=c$irc$id$orig_p, $resp_h = c$irc$id$resp_h, $resp_p=c$irc$id$resp_p, $nick=nick, $user=user, $host=host, $real_name=real_name);
    irc_whois_vec += rec;
}