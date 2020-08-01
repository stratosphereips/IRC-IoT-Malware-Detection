module Strato17;

type irc_whoischannel_record: record {
    ts: time &log;
    orig_h: addr &log;
    orig_p: port &log;
    resp_h: addr &log;
    resp_p: port &log;

    nick: string &log;
    chans: string &log;
};

global irc_who_vec: vector of irc_whoischannel_record = vector();

export {
   redef enum Log::ID += { LOG };
}

event zeek_init() {
   Log::create_stream(Strato17::LOG, [$columns=irc_whoischannel_record, $path="irc_whoischannel"]);
}

event zeek_done() {
   for (i in irc_who_vec) {
       Log::write( Strato17::LOG, irc_who_vec[i]);
   }
}

# Command: WHOIS
# Parameters: [ <target> ] <mask> *( "," <mask> )
# 
# This command is used to query information about particular user.
# The server will answer this command with several numeric messages
# indicating different statuses of each user which matches the mask (if
# you are entitled to see them).  If no wildcard is present in the
# <mask>, any information about that nick which you are allowed to see
# is presented.
event irc_whois_channel_line(c: connection, is_orig: bool, nick: string, chans: string_set) {
    local chans_log: string = "";
    for (chan in chans) {
        chans_log += chan + ",";
    }
    local rec: irc_whoischannel_record = irc_whoischannel_record($ts=c$irc$ts, $orig_h=c$irc$id$orig_h, $orig_p=c$irc$id$orig_p, $resp_h = c$irc$id$resp_h, $resp_p=c$irc$id$resp_p, $nick=nick, $chans=chans_log);
    irc_who_vec += rec;
}