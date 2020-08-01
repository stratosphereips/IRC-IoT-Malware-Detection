module Strato4;

type irc_globalusers_record: record {
    ts: time &log;
    orig_h: addr &log;
    orig_p: port &log;
    resp_h: addr &log;
    resp_p: port &log;

    prefix: string &log;
    msg: string &log;
};

global irc_globalusers_vec: vector of irc_globalusers_record = vector();

export {
   redef enum Log::ID += { LOG };
}

event zeek_init() {
   Log::create_stream(Strato4::LOG, [$columns=irc_globalusers_record, $path="irc_globalusers"]);
}

event zeek_done() {
   for (i in irc_globalusers_vec) {
       Log::write( Strato4::LOG, irc_globalusers_vec[i]);
   }
}


# Generated for an IRC reply of type globalusers.
# C:	The connection.
# Is_orig:	True if the command was sent by the originator of the TCP connection.
# Prefix:	The optional prefix coming with the command. IRC uses the prefix to indicate the true origin of a message.
# Msg:	The message coming with the reply.
event irc_global_users(c: connection, is_orig: bool, prefix: string, msg: string) {
    if (c?$irc) {
        local rec: irc_globalusers_record = irc_globalusers_record($ts=c$irc$ts, $orig_h=c$irc$id$orig_h, $orig_p=c$irc$id$orig_p, $resp_h = c$irc$id$resp_h, $resp_p=c$irc$id$resp_p, $prefix=prefix, $msg=msg);
        irc_globalusers_vec += rec;
    }
}
