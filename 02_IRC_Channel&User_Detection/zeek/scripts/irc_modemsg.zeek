@load base/bif/plugins/Zeek_IRC.events.bif.zeek

module Strato8;

type irc_modemsg_record: record {
    ts: time &log;
    orig_h: addr &log;
    orig_p: port &log;
    resp_h: addr &log;
    resp_p: port &log;
    
    prefix: string &log;
    params: string &log;
};

global irc_modemsg_vec: vector of irc_modemsg_record = vector();

export {
   redef enum Log::ID += { LOG };
}

event zeek_init() {
   Log::create_stream(Strato8::LOG, [$columns=irc_modemsg_record, $path="irc_modemsg"]);
}

event zeek_done() {
   for (i in irc_modemsg_vec) {
       Log::write( Strato8::LOG, irc_modemsg_vec[i]);
   }
}

# Generated for IRC messages of type mode. This event is generated for messages coming from both the client and the server.
# C:	The connection.
# Is_orig:	True if the command was sent by the originator of the TCP connection.
# Prefix:	The optional prefix coming with the command. IRC uses the prefix to indicate the true origin of a message.
# Params:	The parameters coming with the message.
event irc_mode_message(c: connection, is_orig: bool, prefix: string, params: string) {
    if (c?$irc) {
        local rec: irc_modemsg_record = irc_modemsg_record($ts=c$irc$ts, $orig_h=c$irc$id$orig_h, $orig_p=c$irc$id$orig_p, $resp_h = c$irc$id$resp_h, $resp_p=c$irc$id$resp_p, $prefix=prefix, $params=params);
        irc_modemsg_vec += rec;        
    }
}
