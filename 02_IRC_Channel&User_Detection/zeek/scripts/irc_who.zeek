module Strato15;

type irc_who_record: record {
    ts: time &log;
    orig_h: addr &log;
    orig_p: port &log;
    resp_h: addr &log;
    resp_p: port &log;

    target_nick: string &log;
    channel: string &log;
    user: string &log;
    host: string &log;
    server: string &log;
    nick: string &log;
    params: string &log;
    hops: count &log;
    real_name: string &log;
};

global irc_who_vec: vector of irc_who_record = vector();

export {
   redef enum Log::ID += { LOG };
}

event zeek_init() {
   Log::create_stream(Strato15::LOG, [$columns=irc_who_record, $path="irc_who"]);
}

event zeek_done() {
   for (i in irc_who_vec) {
       Log::write( Strato15::LOG, irc_who_vec[i]);
   }
}

# Command: WHO
# Parameters: [ <mask> [ "o" ] ]
# The WHO command is used by a client to generate a query which returns
# a list of information which 'matches' the <mask> parameter given by
# the client.  In the absence of the <mask> parameter, all visible
# (users who aren't invisible (user mode +i) and who don't have a
# common channel with the requesting client) are listed.  The same
# result can be achieved by using a <mask> of "0" or any wildcard which
# will end up matching every visible user.
# 
# The <mask> passed to WHO is matched against users' host, server, real
# name and nickname if the channel <mask> cannot be found.
event irc_who_line(c: connection, is_orig: bool, target_nick: string, channel: string, user: string, host: string, server: string, nick: string, params: string, hops: count, real_name: string) {
    if (c?$irc) {
        local rec: irc_who_record = irc_who_record($ts=c$irc$ts, $orig_h=c$irc$id$orig_h, $orig_p=c$irc$id$orig_p, $resp_h = c$irc$id$resp_h, $resp_p=c$irc$id$resp_p, $target_nick=target_nick, $channel=channel, $user=user, $host=host, $server=server,$nick=nick, $params=params, $hops=hops, $real_name=real_name);
        irc_who_vec += rec;
    }
}